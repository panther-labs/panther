package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/cmd/opstools/requeue"
)

const (
	banner = "moves messages from one sqs queue to another"
)

var (
	ACCOUNTID = flag.String("accountid", "", "The AWS account id where the queues exists")
	REGION    = flag.String("region", "", "The AWS region where the queues exists")
	FROMQ     = flag.String("from.q", "", "The name of the queue to copy from")
	TOQ       = flag.String("to.q", "", "The name of the queue to copy to")
)

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(),
		"%s %s\nUsage:\n",
		filepath.Base(os.Args[0]), banner)
	flag.PrintDefaults()
}

func init() {
	flag.Usage = usage
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

	flag.Parse()

	if *ACCOUNTID == "" {
		err = errors.New("-accountid not set")
		return
	}
	if *REGION == "" {
		err = errors.New("-region not set")
		return
	}
	if *FROMQ == "" {
		err = errors.New("-from.q not set")
		return
	}
	if *TOQ == "" {
		err = errors.New("-to.q not set")
		return
	}
}

func main() {
	validateFlags()

	sess, err := session.NewSession(&aws.Config{Region: REGION})
	if err != nil {
		log.Fatal(err)
		return
	}

	err = requeue.Requeue(sqs.New(sess), *FROMQ, *TOQ)
	if err != nil {
		log.Fatal(err)
	}
}
