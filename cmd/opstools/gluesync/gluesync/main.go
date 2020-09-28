package main

import (
	"context"
	"flag"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/panther-labs/panther/cmd/opstools"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/gluetasks"
	"golang.org/x/sync/errgroup"
)

var opts = struct {
	DryRun         *bool
	Debug          *bool
	Region         *string
	NumWorkers     *int
	MaxConnections *int
	MaxRetries     *int
	Prefix         *string
}{
	DryRun:         flag.Bool("dry-run", false, "Scan for partitions to sync without applying any modifications"),
	Debug:          flag.Bool("debug", false, "Enable additional logging"),
	Region:         flag.String("region", "", "Set the AWS region to run on"),
	MaxRetries:     flag.Int("max-retries", 12, "Max retries for AWS requests"),
	MaxConnections: flag.Int("max-connections", 100, "Max number of connections to AWS"),
	NumWorkers:     flag.Int("workers", 8, "Number of parallel workers for each table"),
	Prefix:         flag.String("prefix", "", "A prefix to filter log type names"),
}

func main() {
	flag.Parse()
	log := opstools.MustBuildLogger(*opts.Debug)

	var matchPrefix string
	if optPrefix := *opts.Prefix; optPrefix != "" {
		matchPrefix = awsglue.GetTableName(optPrefix)
	}

	sess, err := session.NewSession(&aws.Config{
		Region:     opts.Region,
		MaxRetries: opts.MaxRetries,
		HTTPClient: opstools.NewHTTPClient(*opts.MaxConnections, 0),
	})
	if err != nil {
		log.Fatalf("failed to start AWS session: %s", err)
	}
	glueAPI := glue.New(sess)
	group, ctx := errgroup.WithContext(context.Background())
	tasks := []gluetasks.SyncDatabaseTables{
		{
			DatabaseName: awsglue.LogProcessingDatabaseName,
			DryRun:       *opts.DryRun,
			MatchPrefix:  matchPrefix,
			NumWorkers:   *opts.NumWorkers,
		},
		{
			DatabaseName:         awsglue.RuleErrorsDatabaseName,
			AfterTableCreateTime: true,
			DryRun:               *opts.DryRun,
			MatchPrefix:          matchPrefix,
			NumWorkers:           *opts.NumWorkers,
		},
		{
			DatabaseName:         awsglue.RuleMatchDatabaseName,
			AfterTableCreateTime: true,
			DryRun:               *opts.DryRun,
			MatchPrefix:          matchPrefix,
			NumWorkers:           *opts.NumWorkers,
		},
	}
	log.Info("sync started")
	for i := range tasks {
		task := &tasks[i]
		group.Go(func() error {
			return task.Run(ctx, glueAPI, log.Desugar())
		})
	}
	if err := group.Wait(); err != nil {
		log.Fatalf("sync failed: %s", err)
	}
	log.Info("sync complete")
}
