package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/athenaviews"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/gluetables"
	"github.com/panther-labs/panther/pkg/awscfn"
	"github.com/panther-labs/panther/pkg/genericapi"
	"github.com/panther-labs/panther/pkg/prompt"
	"github.com/panther-labs/panther/tools/cfnstacks"
)

const (
	banner = "updates glue table and partition schemas"

	dateFormat = "2006-01-02"
)

var (
	REGION = flag.String("region", "",
		"The Panther AWS region (optional, defaults to session env vars) where the queue exists.")
	REGEXP = flag.String("regexp", "",
		"Regular expression used to filter the set of log types updated, defaults to all log types (no regexp)")
	START = flag.String("start", "",
		"Start date of the form YYYY-MM-DD, if not set use the create date of the table")
	INTERACTIVE = flag.Bool("interactive", true,
		"If true, prompt for required flags if not set")
	VERBOSE = flag.Bool("verbose", true,
		"Enable verbose logging")

	logger *zap.SugaredLogger

	startDate    time.Time
	matchLogType *regexp.Regexp

	version string // we expect this to be set by the build tool as `-X main.version=<some version>`

	// clients
	athenaClient *athena.Athena
	cfnClient    *cloudformation.CloudFormation
	glueClient   *glue.Glue
	lambdaClient *lambda.Lambda
	s3Client     *s3.S3
)

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(),
		"%s %s\nUsage:\n",
		filepath.Base(os.Args[0]), banner)
	flag.PrintDefaults()
	fmt.Printf("Panther version: %s\n", version)
}

func init() {
	flag.Usage = usage

	config := zap.NewDevelopmentConfig() // DEBUG by default
	if !*VERBOSE {
		// In normal mode, hide DEBUG messages and file/line numbers
		config.DisableCaller = true
		config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}

	// Always disable error traces and use color-coded log levels and short timestamps
	config.DisableStacktrace = true
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	rawLogger, err := config.Build()
	if err != nil {
		log.Fatalf("failed to build logger: %s", err)
	}
	zap.ReplaceGlobals(rawLogger)
	logger = rawLogger.Sugar()
}

func main() {
	flag.Parse()

	sess, err := session.NewSession()
	if err != nil {
		logger.Fatal(err)
		return
	}
	athenaClient = athena.New(sess)
	cfnClient = cloudformation.New(sess)
	glueClient = glue.New(sess)
	lambdaClient = lambda.New(sess)
	s3Client = s3.New(sess)

	if *REGION != "" { //override
		sess.Config.Region = REGION
	} else {
		REGION = sess.Config.Region
	}

	promptFlags()
	validateFlags()

	// for each registered table, update the table, for each time partition, update the schema
	for _, table := range updateRegisteredTables() {
		name := fmt.Sprintf("%s.%s", table.DatabaseName(), table.TableName())

		if *VERBOSE {
			logger.Infof("syncing partitions for %s", name)
		}
		_, err := table.SyncPartitions(glueClient, s3Client, startDate, nil)
		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == glue.ErrCodeEntityNotFoundException {
				logger.Infof("%s is not deployed, skipping", name)
			} else {
				logger.Fatalf("failed syncing %s: %v", name, err)
			}
		}
	}
}

func promptFlags() {
	if !*INTERACTIVE {
		return
	}

	if *START == "" {
		startDateText := prompt.Read("Enter a day as YYYY-MM-DD to start update (or <enter> to use create date on tables): ",
			prompt.DateValidator)
		if startDateText != "" {
			startDate, _ = time.Parse(dateFormat, startDateText) // no error check already validated
		}
	}

	if *REGEXP == "" {
		*REGEXP = prompt.Read("Enter regex to select a subset of log types (or <enter> for all tables): ",
			prompt.RegexValidator)
	}
}

func validateFlags() {
	var err error
	defer func() {
		if err != nil {
			fmt.Printf("%s\n", err)
			flag.Usage()
			os.Exit(-2)
		}
	}()

	matchLogType, err = regexp.Compile(*REGEXP)
	if err != nil {
		err = errors.Wrapf(err, "cannot read -regexp")
	}
}

func updateRegisteredTables() (tables []*awsglue.GlueTableMetadata) {
	// find the bucket to associate with the table
	const processDataBucketStack = cfnstacks.Bootstrap
	outputs := awscfn.StackOutputs(cfnClient, logger, processDataBucketStack)
	var dataBucket string
	if dataBucket = outputs["ProcessedDataBucket"]; dataBucket == "" {
		logger.Fatalf("could not find processed data bucket in %s outputs", processDataBucketStack)
	}

	// check the version of Panther deployed against what this as compiled against, they _must_ match!
	tagResponse, err := s3Client.GetBucketTagging(&s3.GetBucketTaggingInput{Bucket: &dataBucket})
	if err != nil {
		logger.Fatalf("could not read processed data bucket tags for %$: %s", processDataBucketStack, err)
	}
	var deployedPantherVersion string
	for _, tag := range tagResponse.TagSet {
		if aws.StringValue(tag.Key) == "PantherVersion" {
			deployedPantherVersion = *tag.Value
		}
	}
	if version != deployedPantherVersion {
		logger.Fatalf("deployed Panther version '%s' does not match compiled Panther version '%s'",
			deployedPantherVersion, version)
	}

	var listOutput []*models.SourceIntegration
	var listInput = &models.LambdaInput{
		ListIntegrations: &models.ListIntegrationsInput{},
	}
	if err := genericapi.Invoke(lambdaClient, "panther-source-api", listInput, &listOutput); err != nil {
		logger.Fatalf("error calling source-api to list integrations: %v", err)
	}

	// get unique set of logTypes
	logTypeSet := make(map[string]struct{})
	for _, integration := range listOutput {
		if integration.IntegrationType == models.IntegrationTypeAWS3 {
			for _, logType := range integration.LogTypes {
				logTypeSet[logType] = struct{}{}
			}
		}
	}

	for logType := range logTypeSet {
		if !matchLogType.MatchString(logType) {
			continue
		}

		if *VERBOSE {
			logger.Infof("updating registered tables for %s", logType)
		}
		logTable, ruleTable, err := gluetables.CreateOrUpdateGlueTablesForLogType(glueClient, logType, dataBucket)
		if err != nil {
			logger.Fatalf("error updating table definitions: %v", err)
		}
		tables = append(tables, logTable)
		tables = append(tables, ruleTable)
	}

	// update the views with the new tables
	if err := athenaviews.CreateOrReplaceViews(glueClient, athenaClient); err != nil {
		logger.Fatalf("error updating table views: %v", err)
	}

	return tables
}
