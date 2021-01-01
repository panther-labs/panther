package main

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"context"
	"flag"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/s3/s3manager/s3manageriface"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/panther-labs/panther/cmd/devtools/filegen"
	"github.com/panther-labs/panther/cmd/devtools/filegen/logtype"
	"github.com/panther-labs/panther/cmd/opstools"
)

const (
	uploaderPartSize = 5 * 1024 * 1024
)

var (
	generators []*FileGenerator
)

type FileGenerator struct {
	Name                string
	Generator           filegen.Generator
	Enabled             *bool
	NumberOfFiles       *int
	NumberOfRowsPerFile *int
}

func NewFileGenerator(name string, generator filegen.Generator) *FileGenerator {
	return &FileGenerator{
		Name:                name,
		Generator:           generator,
		Enabled:             flag.Bool(name, false, "true if "+name+" is enabled"),
		NumberOfFiles:       flag.Int(name+".numfiles", 100, "the number of files to generate"),
		NumberOfRowsPerFile: flag.Int(name+".file.numrows", 1000, "the number of rows per file to generate"),
	}
}

func init() {
	generators = append(generators, NewFileGenerator(logtype.AWSS3ServerAccessName, logtype.NewAWSS3ServerAccess()))
	generators = append(generators, NewFileGenerator(logtype.GravitationalTeleportAuditName, logtype.NewGravitationalTeleportAudit()))
}

func main() {
	opstools.SetUsage("writes synthetic log files to s3 for use in benchmarking)")
	opts := struct {
		Bucket      *string
		Prefix      *string
		Start       *string
		End         *string
		Concurrency *int

		Debug  *bool
		Region *string
	}{
		Bucket:      flag.String("bucket", "", "S3 Bucket to write to"),
		Prefix:      flag.String("prefix", "", "Prefix under bucket to write"),
		Start:       flag.String("start", "", "Start date of the form YYYY-MM-DDThh"),
		End:         flag.String("end", "", "End date of the form YYYY-MM-DDThh, if not set then default to now"),
		Concurrency: flag.Int("concurrency", 10, "The number of concurrent uploaders"),

		Debug:  flag.Bool("debug", false, "Enable additional logging"),
		Region: flag.String("region", "", "Set the AWS region to run on"),
	}
	flag.Parse()

	log := opstools.MustBuildLogger(*opts.Debug)

	if *opts.Bucket == "" {
		log.Fatal("-bucket not set")
	}

	var startTime, endTime time.Time

	if *opts.Start == "" {
		log.Fatal("-start must be set")
	}
	startTime, err := time.Parse(filegen.DateFormat, *opts.Start)
	if err != nil {
		log.Fatal("cannot read -start")
	}
	startTime = startTime.Truncate(time.Hour)

	if *opts.End == "" {
		endTime = time.Now().UTC()
	} else {
		endTime, err = time.Parse(filegen.DateFormat, *opts.End)
		if err != nil {
			log.Fatal("cannot read -end")
		}
	}
	endTime = endTime.Truncate(time.Hour)

	if endTime.Before(startTime) {
		log.Fatal("-end is before -start")
	}

	// configure enabled generators
	var enabledGenerators []*FileGenerator
	for _, fileGenerator := range generators {
		if *fileGenerator.Enabled {
			log.Debugf("%s enabled with %d rows per file and %d files",
				fileGenerator.Name, *fileGenerator.NumberOfRowsPerFile, *fileGenerator.NumberOfFiles)
			fileGenerator.Generator.WithRows(*fileGenerator.NumberOfRowsPerFile)
			enabledGenerators = append(enabledGenerators, fileGenerator)
		}
	}

	if len(enabledGenerators) == 0 {
		log.Fatal("no log types enabled")
	}

	sess, err := session.NewSession()
	if err != nil {
		log.Fatal(err)
		return
	}

	if *opts.Region != "" { //override
		sess.Config.Region = opts.Region
	}

	s3Client := s3.New(sess)

	fileChan := make(chan *filegen.File, *opts.Concurrency)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var uploaderGroup errgroup.Group
	for i := 0; i < *opts.Concurrency; i++ {
		uploaderGroup.Go(func() error {
			uploader := s3manager.NewUploaderWithClient(s3Client)
			if err := upload(ctx, *opts.Bucket, *opts.Prefix, fileChan, uploader, log); err != nil {
				cancel()
				return err
			}
			return nil
		})
	}

	generate(startTime, endTime, enabledGenerators, fileChan)

	err = uploaderGroup.Wait()
	if err != nil {
		log.Fatalf("error uploading data: %v", err)
	}
}

func generate(startHour, endHour time.Time, fileGenerators []*FileGenerator, fileChan chan *filegen.File) {
	afterEndHour := endHour.Add(time.Second)
	for hour := startHour; hour.Before(afterEndHour); hour = hour.Add(time.Hour) {
		for _, fileGenerator := range fileGenerators {
			for i := 0; i < *fileGenerator.NumberOfFiles; i++ {
				fileChan <- fileGenerator.Generator.NewFile(hour)
			}
		}
	}
	close(fileChan) // signal uploaders we are done
}

func upload(ctx context.Context, bucket, prefix string, fileChan chan *filegen.File,
	uploader s3manageriface.UploaderAPI, log *zap.SugaredLogger) error {

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case file, more := <-fileChan:
			if !more {
				return nil
			}
			path := prefix + "/" + file.Name
			size := file.Data.Len()
			log.Debugf("uploading %s/%s (%d bytes)", bucket, path, size)
			input := &s3manager.UploadInput{
				Body:   file.Data,
				Bucket: &bucket,
				Key:    aws.String(path),
			}
			_, err := uploader.Upload(input, func(u *s3manager.Uploader) { // calc the concurrency based on payload
				u.Concurrency = (size / uploaderPartSize) + 1 // if it evenly divides an extra won't matter
				u.PartSize = uploaderPartSize
			})
			if err != nil {
				return errors.Wrapf(err, "upload failed for %v", input)
			}
		}
	}
}
