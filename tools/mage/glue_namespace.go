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

	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/magefile/mage/mg"

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
	matchTableName, err := regexp.Compile(enteredText)
	if err != nil {
		logger.Fatal(err)
	}

	enteredText = promptUser("Please input start day (YYYY-MM-DD): ", dateValidator)
	startDay, _ := time.Parse(gluePartitionDateFormat, enteredText) // no error check already validated

	enteredText = promptUser("Please input end day (YYYY-MM-DD): ", dateValidator)
	endDay, _ := time.Parse(gluePartitionDateFormat, enteredText) // no error check already validated

	endDay = endDay.Add(time.Hour * 23) // move to last hour of the day

	if startDay.After(endDay) {
		logger.Fatalf("start day (%s) cannot be after end day (%s)", startDay, endDay)
	}

	syncPartitions(glueClient, matchTableName, startDay, endDay)
}

func syncPartitions(glueClient *glue.Glue, matchTableName *regexp.Regexp, startDay, endDay time.Time) {
	const concurrency = 10
	updateChan := make(chan *gluePartitionUpdate, concurrency)

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
		logger.Infof("syncing %s", name)
		for timeBin := startDay; !timeBin.After(endDay); timeBin = table.Timebin().Next(timeBin) {
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

func dateValidator(text string) error {
	if _, err := time.Parse(gluePartitionDateFormat, text); err != nil {
		return fmt.Errorf("invalid date: %v", err)
	}
	return nil
}

type gluePartitionUpdate struct {
	table *awsglue.GlueMetadata
	at    time.Time
}
