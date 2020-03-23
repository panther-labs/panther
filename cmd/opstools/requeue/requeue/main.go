package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/cmd/opstools/requeue"
)

const (
	banner = "moves messages from one sqs queue to another"
)

var (
	REGION = flag.String("region", "", "The AWS region where the queues exists (optional, defaults to session env vars)")
	FROMQ  = flag.String("from.q", "", "The name of the queue to copy from")
	TOQ    = flag.String("to.q", "", "The name of the queue to copy to")
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

func main() {
	flag.Parse()

	sess, err := session.NewSession()
	if err != nil {
		log.Fatal(err)
		return
	}

	if *REGION != "" { //override
		sess.Config.Region = REGION
	}

	validateFlags()

	err = requeue.Requeue(sqs.New(sess), *FROMQ, *TOQ)
	if err != nil {
		log.Fatal(err)
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

	if *FROMQ == "" {
		err = errors.New("-from.q not set")
		return
	}
	if *TOQ == "" {
		err = errors.New("-to.q not set")
		return
	}
}
