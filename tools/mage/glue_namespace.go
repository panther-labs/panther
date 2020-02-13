package mage

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/magefile/mage/mg"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/pkg/awsglue"
)

// targets for managing Glue tables
type Glue mg.Namespace

const (
	gluePartitionDateFormat = "2006-01-02"
)

// Sync Sync glue table partitions after schema change
func (t Glue) Sync() {
	var enteredText string

	awsSession, err := getSession()
	if err != nil {
		logger.Fatal(err)
	}
	glueClient := glue.New(awsSession)

	enteredText = promptUser("Enter regex to select a subset of tables (or <enter> for all tables): ", regexValidator)
	matchTableName, _ := regexp.Compile(enteredText) // no error check already validated

	syncPartitions(glueClient, matchTableName)
}

func syncPartitions(glueClient *glue.Glue, matchTableName *regexp.Regexp) {
	const concurrency = 10
	updateChan := make(chan *gluePartitionUpdate, concurrency)

	// update to current day at last hour
	endDay := time.Now().UTC().Truncate(time.Hour * 24).Add(time.Hour * 23)

	// delete and re-create concurrently cuz the Glue API is very slow
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			for update := range updateChan {
				err := update.table.SyncPartition(glueClient, update.at)
				if err != nil {
					logger.Error(err) // best effort, let users know there are failures (this can be re-run)
					continue
				}
			}
			wg.Done()
		}()
	}

	// for each table, for each time partition, delete and re-create
	for _, table := range registry.AvailableTables() {
		name := fmt.Sprintf("%s.%s", table.DatabaseName(), table.TableName())
		if !matchTableName.MatchString(name) {
			continue
		}
		createTime, err := getTableCreateTime(glueClient, table)
		if err != nil {
			logger.Fatal(err)
		}
		createTime = createTime.Truncate(time.Hour * 24) // clip to beginning of day
		logger.Infof("syncing %s from %s to %s",
			name, createTime.Format(gluePartitionDateFormat), endDay.Format(gluePartitionDateFormat))
		for timeBin := createTime; !timeBin.After(endDay); timeBin = table.Timebin().Next(timeBin) {
			updateChan <- &gluePartitionUpdate{
				table: table,
				at:    timeBin,
			}
		}
	}

	close(updateChan)
	wg.Wait()
}

func regexValidator(text string) error {
	if _, err := regexp.Compile(text); err != nil {
		return fmt.Errorf("invalid regex: %v", err)
	}
	return nil
}

func getTableCreateTime(glueClient *glue.Glue, table *awsglue.GlueMetadata) (createTime time.Time, err error) {
	// get the CreateTime for the table, start there for syncing
	tableInput := &glue.GetTableInput{
		DatabaseName: aws.String(table.DatabaseName()),
		Name:         aws.String(table.TableName()),
	}
	tableOutput, err := glueClient.GetTable(tableInput)
	if err != nil {
		return createTime, errors.Wrap(err, "cannot get table CreateTime")
	}
	createTime = *tableOutput.Table.CreateTime
	return createTime, nil
}

type gluePartitionUpdate struct {
	table *awsglue.GlueMetadata
	at    time.Time
}
