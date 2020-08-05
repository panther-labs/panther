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
	"github.com/panther-labs/panther/pkg/prompt"
)

const (
	banner = "moves messages from one sqs queue to another"
)

var (
	REGION      = flag.String("region", "", "The AWS region where the queues exists (optional, defaults to session env vars)")
	FROMQ       = flag.String("from.q", "", "The name of the queue to copy from")
	TOQ         = flag.String("to.q", "", "The name of the queue to copy to")
	INTERACTIVE = flag.Bool("interactive", true, "If true, prompt for required flags if not set")
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

	promptFlags()
	validateFlags()

	err = requeue.Requeue(sqs.New(sess), *sess.Config.Region, *FROMQ, *TOQ)
	if err != nil {
		log.Fatal(err)
	}
}

func promptFlags() {
	if !*INTERACTIVE {
		return
	}

	if *FROMQ == "" {
		*FROMQ = prompt.Read("Please enter queue name to read from: ", prompt.NonemptyValidator)
	}

	if *TOQ == "" {
		*TOQ = prompt.Read("Please enter queue name to copy into: ", prompt.NonemptyValidator)
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
