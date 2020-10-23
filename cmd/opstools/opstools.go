package opstools

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
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/hashicorp/go-cleanhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/panther-labs/panther/pkg/awscfn"
	"github.com/panther-labs/panther/tools/cfnstacks"
)

func MustBuildLogger(debug bool) *zap.SugaredLogger {
	config := zap.NewDevelopmentConfig()
	// Always disable and file/line numbers, error traces and use color-coded log levels and short timestamps
	config.DisableCaller = true
	config.DisableStacktrace = true
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	if !debug {
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	logger, err := config.Build()
	if err != nil {
		log.Fatalf("failed to build logger: %s", err)
	}
	return logger.Sugar()
}

func NewHTTPClient(maxConnections int, timeout time.Duration) *http.Client {
	transport := cleanhttp.DefaultPooledTransport()
	transport.MaxIdleConnsPerHost = maxConnections
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

func SetUsage(banner string, args ...interface{}) {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"%s %s\nUsage:\n",
			filepath.Base(os.Args[0]), fmt.Sprintf(banner, args...))
		flag.PrintDefaults()
	}
}

// ValidatePantherVersion checks that the compiled version matches deployed version, if not log.Fatal()
func ValidatePantherVersion(sess *session.Session, log *zap.SugaredLogger, masterStack, compiledVersion string) {
	cfnClient := cloudformation.New(sess)

	// find the bucket to associate with the table
	bootstrapStack, err := cfnstacks.GetBootstrapStack(cfnClient, masterStack)
	if err != nil {
		log.Fatal(err)
	}
	outputs, err := awscfn.StackOutputs(cfnClient, bootstrapStack)
	if err != nil {
		log.Fatal(err)
	}
	var dataBucket string
	if dataBucket = outputs["ProcessedDataBucket"]; dataBucket == "" {
		log.Fatalf("could not find processed data bucket in %s outputs", bootstrapStack)
	}

	// check the version of Panther deployed against what this as compiled against, they _must_ match!
	s3Client := s3.New(sess)
	tagResponse, err := s3Client.GetBucketTagging(&s3.GetBucketTaggingInput{Bucket: &dataBucket})
	if err != nil {
		log.Fatalf("could not read processed data bucket tags for %$: %s", bootstrapStack, err)
	}
	var deployedPantherVersion string
	for _, tag := range tagResponse.TagSet {
		if aws.StringValue(tag.Key) == "PantherVersion" {
			deployedPantherVersion = *tag.Value
		}
	}

	if compiledVersion != deployedPantherVersion {
		log.Fatalf("deployed Panther version '%s' does not match compiled Panther version '%s'",
			deployedPantherVersion, compiledVersion)
	}
}
