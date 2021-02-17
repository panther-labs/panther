// flushrsc opstool removes all entries from the panther-resources table where deleted=true
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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/cmd/opstools"
	"github.com/panther-labs/panther/pkg/awsbatch/dynamodbbatch"
	"github.com/panther-labs/panther/tools/mage/util"
)

const tableName = "panther-resources"
const maxBackoff = 60 * time.Second

// version set by mage build:tools
var version string
var log *zap.SugaredLogger

// Main will
// Get user input to determine flush, inspect, or save
// If save, create a file where entries will be saved
// If inspect, ignore save and flush
func main() {
	startTime := time.Now()
	defer handlePanic()

	// CMD line options
	debug, flush, inspect, save, versionOpt := getOpts()

	// Guarantee:
	//   -version overwrites all other options
	//   - inspect overwrites save and flush
	//   - save overwrites flush
	flush = flush && !save && !inspect && !versionOpt
	save = save && !inspect && !versionOpt
	inspect = inspect && !versionOpt

	// log is the only package level variable (not including version from ops tool)
	log = opstools.MustBuildLogger(debug)
	log.Debug("MUST LOGGER SUCCESS")
	log.Debug("STARTEPOCH=", startTime.Unix())

	// writeCloser used to pass either nil or *os.File
	var saveWriteCloser io.WriteCloser
	var savePath string

	// Print and init options / option depts
	switch {
	case flush:
		log.Info("FLUSH")
	case inspect:
		log.Info("INSPECT")
	case save: // -save Save the IDS to the os.File returned from getSaveFile(startTime)
		log.Info("SAVE")
		saveWriteCloser, savePath = mustGetSaver(startTime)
		defer func() {
			log.Infof("%s", savePath)
			saveWriteCloser.Close()
			if err := recover(); err != nil {
				if err, ok := err.(error); ok && err != nil {
					log.Error("save encountered an error... removing save file")
					rmerr := os.Remove(savePath)
					check(rmerr)
					// Check the original error
					check(err)
				}
			}
		}()
	case versionOpt: // -version prints build metadata
		_, BIN, ARCH, OS := buildInfo()
		log.Info("ARCH=", ARCH)
		log.Info("BIN=", BIN)
		log.Info("OS=", OS)
		log.Info("VERSION=", version)
		return // exit without proceeding
	default:
		usage()
		return // exit without proceeding
	}

	// we need aws for only after this point.
	awsSession := session.Must(session.NewSession())
	log.Debug("AWS SESSION MUST SUCCESS")
	dbSvc := dynamodb.New(awsSession)

	// Execute the scanpages, save, and flush (depending on params)
	MustFlushSaveInspectResources(log, dbSvc, flush, inspect, saveWriteCloser)
	log.Infof("Completed in %.2f Seconds", time.Since(startTime).Seconds())
}

// Flush runs all the inspect, flush, and save commands. This method can be called on its own
// assuming the inputs are valid.
func MustFlushSaveInspectResources(logger *zap.SugaredLogger, svc *dynamodb.DynamoDB, flush, inspect bool, saveWriter io.Writer) {
	// check inputs or panic with inputs requires
	switch {
	case flush, inspect, saveWriter != nil:
	default:
		check(errors.New("MustFlushSaveInspectResources requires flush, inspect, or a valid writer"))
	}

	// Ensure inspect over-rides any flush or save
	flush = flush && !inspect

	// Store write requests for items scanned in svc.ScanPages using the scanInput expression
	deleteRequests := []*dynamodb.WriteRequest{}

	// Build the scan expression
	proj := expression.NamesList(expression.Name("id"))
	filt := expression.Name("deleted").Equal(expression.Value(true))
	expr, err := expression.NewBuilder().WithFilter(filt).WithProjection(proj).Build()
	check(err)

	// define params used in call to ScanPages
	scanInput := &dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 aws.String(tableName),
	}
	resultScanner := func(page *dynamodb.ScanOutput, lastPage bool) bool {
		for _, item := range page.Items {
			if saveWriter != nil {
				_, err := saveWriter.Write([]byte(*item["id"].S + "\n"))
				check(err)
				continue
			}
			// Add delete request to the batch set
			deleteEntry := &dynamodb.WriteRequest{DeleteRequest: &dynamodb.DeleteRequest{Key: item}}
			deleteRequests = append(deleteRequests, deleteEntry)
		}
		return !lastPage
	}

	// SCAN THE DYNAMODB
	check(svc.ScanPages(scanInput, resultScanner))
	flush = flush && len(deleteRequests) > 0
	if inspect && len(deleteRequests) > 0 {
		logger.Infof("items pending delete: %v", len(deleteRequests))
		// Set initial size to length of items to add size of required newline characters
		var sumSz int64 = int64(len(deleteRequests))
		for _, item := range deleteRequests {
			sumSz += int64(len(*item.DeleteRequest.Key["id"].S))
		}
		logger.Infof("Save file estimated size: %v", util.ByteCountSI(sumSz))
	}
	if flush {
		// Batch write request parameter containing set of delete item requests
		batchWriteInput := &dynamodb.BatchWriteItemInput{
			RequestItems: map[string][]*dynamodb.WriteRequest{tableName: deleteRequests},
		}
		logger.Debug("Beginning Batch Delete")
		check(dynamodbbatch.BatchWriteItem(svc, maxBackoff, batchWriteInput))
		logger.Debug("Completed Batch Delete")
	}
}

// returns tool Name, GOOS, GOARCH, Binary Name,.
func buildInfo() (NAME, BIN, ARCH, OS string) {
	BIN = filepath.Base(os.Args[0])
	versionMeta := strings.Split(BIN, "-")
	ARCH = versionMeta[2]
	NAME = versionMeta[0]
	OS = versionMeta[1]
	return
}

// panic on any non nil error
func check(err error) {
	if err != nil {
		panic(err)
	}
}

// parses user input for options -debug, -flush, -inspect, -save, -version
func getOpts() (debug, flush, inspect, save, versionOpt bool) {
	cliDebug := flag.Bool("debug", false, "Enable debug logging")
	cliFlush := flag.Bool("flush", false, "Remove entries from the panther-resources table where deleted=true")
	cliInspect := flag.Bool("inspect", false, "Print number of panther-resources entries where delete=true and the estimated save file size")
	cliSave := flag.Bool("save", false, "Save Id's of panther-resources entries where delete=true to ./flush_resource_ids_<start_epoch>")
	cliVersion := flag.Bool("version", false, "Print ARCH, BIN, OS, and VERSION")
	flag.Parse()
	debug = *cliDebug
	flush = *cliFlush
	inspect = *cliInspect
	save = *cliSave
	versionOpt = *cliVersion
	// If Inspect is specified we disable save and flush
	flush = flush && !inspect
	save = save && !inspect
	return
}

// Error handler for all errors in this ops tool.
func handlePanic() {
	if err := recover(); err != nil {
		if err, ok := err.(awserr.Error); ok {
			switch err {
			case credentials.ErrNoValidProvidersFoundInChain:
				log.Debug("credentials.ErrNoValidProvidersFoundInChain")
				log.Error("AWS NoCredentialProviders Error: No valid providers in chain")
				log.Info("Double check your aws credentials")
			default:
				log.Debug("Unhandled aws error")
				log.Error("aws error: %v", err)
			}
		} else {
			log.Debug("UNHANDLED ERROR", err)
			log.Error("%v", err)
		}
	}
}

// Returns the current working directory, panic if error
func mustCWD() string {
	cwd, err := os.Getwd()
	check(err)
	return cwd
}

// Returns an io.WriteCloser with *os.File as the underlying struct
func mustGetSaver(filePostfix time.Time) (result io.WriteCloser, saveFPath string) {
	// save file basename
	basename := fmt.Sprintf("flush_resource_ids_%v", filePostfix.Unix())
	// full path where our save file will be created
	saveFPath = filepath.Join(mustCWD(), basename)
	// Create the file, must, assign the return interface
	saveFile, err := os.Create(saveFPath)
	check(err)
	result = saveFile
	return
}

// Prints tool usage
func usage() {
	// This makes things pretty
	printfln := func(args ...interface{}) {
		if len(args) == 1 {
			fmt.Fprintf(flag.CommandLine.Output(), args[0].(string))
		} else if len(args) > 1 {
			fmt.Fprintf(flag.CommandLine.Output(), args[0].(string), args[1:]...)
		}
		fmt.Fprintf(flag.CommandLine.Output(), "\n")
	}
	name, binary, _, _ := buildInfo()
	printfln("\n%v\n", name)
	printfln("  Remove entries from the resources table where entry deleted=true\n")
	printfln("  Entries in the resources table are set as deleted and scheduled for deletion.")
	printfln("  This can lead to a large number of entries that have been deleted from Panther")
	printfln("  but are pending deletion from the resources table.\n")
	printfln("  This tool removes all entries from the resources table which have been deleted")
	printfln("  from Panther but are pending deletion from the table.\n")
	printfln("  Save is not necessary for most users. Use inspect before save to view the number")
	printfln("  of items with delete=true, and to see the estimated file size of the save file.\n")
	printfln("  Inspect and version will return without running save or flush.\n")
	printfln("  Save will not create a file when the resources table has no entries pending")
	printfln("  deletion\n")
	printfln("  Flush is the only option that will remove entries from the resources table\n")
	printfln("REQUIREMENTS:\n")
	printfln("  This tool requires aws credentials with dynamodb panther-resources table permissions:\n")
	printfln("  BatchWriteItem")
	printfln("  Scan\n")
	printfln("USAGE:\n\n  %v <options>\n", binary)
	printfln("Where options are:\n")
	flag.PrintDefaults()
	printfln()
}
