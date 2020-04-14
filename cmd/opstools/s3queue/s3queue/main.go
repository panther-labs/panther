package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/panther-labs/panther/cmd/opstools/s3queue"
)

const (
	banner = "lists s3 objects and posts s3 notifications to log processor queue"
)

var (
	REGION      = flag.String("region", "", "The AWS region (optional, defaults to session env vars) where the queues and bucket exist.")
	ACCOUNT     = flag.String("account", "", "The AWS account id (optional, defaults to session account) where the bucket exists.")
	S3PATH      = flag.String("s3path", "", "The s3 path to list (e.g., s3://<bucket>/<prefix>).")
	CONCURRENCY = flag.Int("concurrency", 50, "The number of concurrent sqs writer go routines")
	LIMIT       = flag.Uint64("limit", 0, "If non-zero, then limit the number of files to this number.")
	TOQ         = flag.String("queue", "panther-input-data-notifications-queue", "The name of the log processor queue to send notifications.")
	VERBOSE     = flag.Bool("verbose", false, "Enable verbose logging")

	logger *zap.SugaredLogger
)

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(),
		"%s %s\nUsage:\n",
		filepath.Base(os.Args[0]), banner)
	flag.PrintDefaults()
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

	if *REGION != "" { //override
		sess.Config.Region = REGION
	}

	if *ACCOUNT == "" {
		identity, err := sts.New(sess).GetCallerIdentity(&sts.GetCallerIdentityInput{})
		if err != nil {
			logger.Fatalf("failed to get caller identity: %v", err)
		}
		ACCOUNT = identity.Account
	}

	validateFlags()

	startTime := time.Now()
	if *VERBOSE {
		if *LIMIT > 0 {
			logger.Infof("sending %d files from %s to %s", *LIMIT, *S3PATH, *TOQ)
		} else {
			logger.Infof("sending files from %s to %s", *S3PATH, *TOQ)
		}
	}

	stats := &s3queue.Stats{}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		caught := <-sig // wait for it
		logger.Fatalf("caught %v, sent %d files (%.2fMB) to %s in %v",
			caught, stats.NumFiles, float32(stats.NumBytes)/(1024.0*1024.0), *TOQ, time.Since(startTime))
	}()

	err = s3queue.S3Queue(sess, *ACCOUNT, *S3PATH, *TOQ, *CONCURRENCY, *LIMIT, *VERBOSE, stats)
	if err != nil {
		logger.Fatal(err)
	} else {
		logger.Infof("sent %d files (%.2fMB) to %s in %v",
			stats.NumFiles, float32(stats.NumBytes)/(1024.0*1024.0), *TOQ, time.Since(startTime))
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

	if *S3PATH == "" {
		err = errors.New("-s3path not set")
		return
	}
	if *TOQ == "" {
		err = errors.New("-queue not set")
		return
	}
}
