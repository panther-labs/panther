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
	"flag"
	"sync/atomic"
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
		NumberOfFiles:       flag.Int(name+".numfiles", 100, "the number of files to generate each hour"),
		NumberOfRowsPerFile: flag.Int(name+".file.numrows", 1000, "the number of rows per file to generate"),
	}
}

func init() {
	generators = append(generators, NewFileGenerator(logtype.AWSS3ServerAccessName, logtype.NewAWSS3ServerAccess()))
	generators = append(generators, NewFileGenerator(logtype.AWSCloudTrailName, logtype.NewAWSCloudTrail()))
	generators = append(generators, NewFileGenerator(logtype.GravitationalTeleportAuditName, logtype.NewGravitationalTeleportAudit()))
}

type flagOpts struct {
	Bucket      *string
	Prefix      *string
	Start       *string
	End         *string
	TBPerDay    *float64
	Concurrency *int

	Debug  *bool
	Region *string

	// set by Validate()
	startTime, endTime time.Time
}

func (opts *flagOpts) Validate() (err error) {
	if *opts.Bucket == "" {
		return errors.Errorf("-bucket not set")
	}

	if *opts.Start == "" {
		return errors.Errorf("-start must be set")
	}
	opts.startTime, err = time.Parse(filegen.DateFormat, *opts.Start)
	if err != nil {
		return errors.Errorf("cannot read -start")
	}
	opts.startTime = opts.startTime.Truncate(time.Hour)

	if *opts.End == "" {
		opts.endTime = time.Now().UTC()
	} else {
		opts.endTime, err = time.Parse(filegen.DateFormat, *opts.End)
		if err != nil {
			return errors.Errorf("cannot read -end")
		}
	}
	opts.endTime = opts.endTime.Truncate(time.Hour)

	if opts.endTime.Before(opts.startTime) {
		return errors.Errorf("-end is before -start")
	}

	if *opts.Concurrency < 1 {
		return errors.Errorf("-concurrency must be >= 1")
	}

	return err
}

func main() {
	opstools.SetUsage("writes synthetic log files to s3 for use in benchmarking")
	opts := flagOpts{
		Bucket: flag.String("bucket", "", "S3 Bucket to write to"),
		Prefix: flag.String("prefix", "", "Prefix under bucket to write"),
		Start:  flag.String("start", "", "Start date of the form YYYY-MM-DDThh"),
		End:    flag.String("end", "", "End date of the form YYYY-MM-DDThh, if not set then default to now"),
		TBPerDay: flag.Float64("tbPerDay", 0.0,
			"If non zero, ignore number of files set and write until this amount of data has been reached."),
		Concurrency: flag.Int("concurrency", 10, "The number of concurrent uploaders"),

		Debug:  flag.Bool("debug", false, "Enable additional logging"),
		Region: flag.String("region", "", "Set the AWS region to run on"),
	}
	flag.Parse()

	log := opstools.MustBuildLogger(*opts.Debug)

	if err := opts.Validate(); err != nil {
		log.Fatalf("error parsing flags: %s", err)
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

	var uploaderGroup errgroup.Group
	for i := 0; i < *opts.Concurrency; i++ {
		uploaderGroup.Go(func() error {
			uploader := s3manager.NewUploaderWithClient(s3Client)
			if err := upload(*opts.Bucket, *opts.Prefix, fileChan, uploader, log); err != nil {
				return err
			}
			return nil
		})
	}

	beginRun := time.Now()

	generateBy := generateBy{
		startHour:      opts.startTime.UTC(),
		endHour:        opts.endTime.UTC(),
		fileGenerators: enabledGenerators,
		fileChan:       fileChan,
		concurrency:    *opts.Concurrency,
	}

	if *opts.TBPerDay != 0.0 {
		durationDays := (opts.endTime.Sub(opts.startTime).Hours() + 1.0) / 24.0
		bytesPerDay := *opts.TBPerDay * 1024 * 1024 * 1024 * 1024
		generateBy.targetUncompressedBytes = uint64(bytesPerDay * durationDays)

		log.Infof("generating files by size: %f TB per day (%d bytes) spread over %v to %v (%f days) to s3://%s/%s",
			*opts.TBPerDay, generateBy.targetUncompressedBytes,
			opts.startTime.Format(filegen.DateFormat), opts.endTime.Format(filegen.DateFormat),
			durationDays,
			*opts.Bucket, *opts.Prefix)
		generateBy.size()
	} else {
		log.Infof("generating files over %v to %v to s3://%s/%s",
			opts.startTime.Format(filegen.DateFormat), opts.endTime.Format(filegen.DateFormat),
			*opts.Bucket, *opts.Prefix)
		generateBy.hour()
	}

	err = uploaderGroup.Wait()

	// always log this first in case of error, so progress is shown
	log.Infof("wrote %d files, %d total bytes, %d total uncompressed bytes in %v to s3://%s/%s",
		generateBy.writtenFiles, generateBy.writtenBytes, generateBy.writtenUncompressedBytes,
		time.Since(beginRun),
		*opts.Bucket, *opts.Prefix)

	if err != nil {
		log.Fatalf("error uploading data: %v", err)
	}
}

type generateBy struct {
	startHour, endHour time.Time
	fileGenerators     []*FileGenerator
	fileChan           chan *filegen.File

	targetUncompressedBytes uint64 // if non-zero stop here

	// managing concurrency
	generateFileChan chan *generateFile
	workerGroup      errgroup.Group
	concurrency      int

	// tallies
	writtenFiles, writtenBytes, writtenUncompressedBytes uint64
}

type generateFile struct {
	fileGenerator filegen.Generator
	hour          time.Time
}

func (gf *generateFile) newFile() *filegen.File {
	return gf.fileGenerator.NewFile(gf.hour)
}

func (gb *generateBy) startWorkers() {
	gb.generateFileChan = make(chan *generateFile, gb.concurrency)

	for i := 0; i < gb.concurrency; i++ {
		gb.workerGroup.Go(func() error {
			for gf := range gb.generateFileChan {
				// drain channel if done
				if gb.targetUncompressedBytes != 0 && gb.writtenUncompressedBytes >= gb.targetUncompressedBytes {
					continue
				}

				f := gf.newFile()
				gb.fileChan <- f
				atomic.AddUint64(&gb.writtenFiles, 1)
				atomic.AddUint64(&gb.writtenBytes, f.TotalBytes())
				atomic.AddUint64(&gb.writtenUncompressedBytes, f.TotalUncompressedBytes())
			}
			return nil
		})
	}
}

func (gb *generateBy) waitWorkers() {
	// signal done, wait
	close(gb.generateFileChan)
	_ = gb.workerGroup.Wait()
}

func (gb *generateBy) hour() {
	defer close(gb.fileChan) // signal uploaders we are done

	gb.startWorkers()
	defer gb.waitWorkers()

	afterEndHour := gb.endHour.Add(time.Second)
	for hour := gb.startHour; hour.Before(afterEndHour); hour = hour.Add(time.Hour) {
		for _, fileGenerator := range gb.fileGenerators {
			for i := 0; i < *fileGenerator.NumberOfFiles; i++ {
				// send to workers
				gb.generateFileChan <- &generateFile{
					fileGenerator: fileGenerator.Generator,
					hour:          hour,
				}
			}
		}
	}
}

func (gb *generateBy) size() {
	defer close(gb.fileChan) // signal uploaders we are done

	gb.startWorkers()
	defer gb.waitWorkers()

	afterEndHour := gb.endHour.Add(time.Second)
	for {
		for hour := gb.startHour; hour.Before(afterEndHour); hour = hour.Add(time.Hour) {
			for _, fileGenerator := range gb.fileGenerators {
				// send to workers
				gb.generateFileChan <- &generateFile{
					fileGenerator: fileGenerator.Generator,
					hour:          hour,
				}
				// poll to see if done inside of loop, workers are updating these values
				if gb.targetUncompressedBytes != 0 && gb.writtenUncompressedBytes >= gb.targetUncompressedBytes {
					return
				}
			}
		}
	}
}

func upload(bucket, prefix string, fileChan chan *filegen.File, uploader s3manageriface.UploaderAPI, log *zap.SugaredLogger) (err error) {
	const maxRetries = 3
	for file := range fileChan {
		if err != nil { // drain channel
			continue
		}

		path := prefix + "/" + file.Name()
		size := file.Data.Len()
		log.Debugf("uploading %s/%s (%d bytes, %d bytes uncompressed)", bucket, path, size, file.TotalUncompressedBytes())
		input := &s3manager.UploadInput{
			Body:   file.Data,
			Bucket: &bucket,
			Key:    aws.String(path),
		}
		// NOTE: the retry look here was needed to recover at high loads and concurrency the failure of the creds refresh
		for i := 0; i < maxRetries; i++ {
			_, err = uploader.Upload(input, func(u *s3manager.Uploader) { // calc the concurrency based on payload
				u.Concurrency = (size / uploaderPartSize) + 1 // if it evenly divides an extra won't matter
				u.PartSize = uploaderPartSize
			})
			if err == nil {
				break // no error break retry loop
			}
			err = errors.Wrapf(err, "upload failed for s3://%s/%s", *input.Bucket, *input.Key)
			time.Sleep(time.Second)
		}
	}
	return err
}
