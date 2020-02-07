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
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/magefile/mage/mg"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/pkg/awsglue"
)

// targets for managing Glue tables
type Glue mg.Namespace

// Sync's all glue table partitions with current table schema (used when table schema changes)
func (t Glue) Sync() error {
	const concurrency = 10
	const dateFormat = "2006-01-02"
	var enteredText string

	awsSession := session.Must(session.NewSession())
	glueClient := glue.New(awsSession)

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Please input matching string to select tables (or <enter> for all tables): ")
	enteredText, _ = reader.ReadString('\n')
	enteredText = strings.TrimSpace(enteredText)
	matchTableName := enteredText

	fmt.Print("Please input start day (YYYY-MM-DD): ")
	enteredText, _ = reader.ReadString('\n')
	enteredText = strings.TrimSpace(enteredText)
	startDay, err := time.Parse(dateFormat, enteredText)
	if err != nil {
		return fmt.Errorf("cannot parse %s as YYYY-MM-DD", enteredText)
	}

	fmt.Print("Please input end day (YYYY-MM-DD): ")
	enteredText, _ = reader.ReadString('\n')
	enteredText = strings.TrimSpace(enteredText)
	endDay, err := time.Parse(dateFormat, enteredText)
	if err != nil {
		return fmt.Errorf("cannot parse %s as YYYY-MM-DD", enteredText)
	}
	endDay = endDay.Add(time.Hour * 23) // move to last hour of the day

	if startDay.After(endDay) {
		return fmt.Errorf("start day (%s) cannot be after end day (%s)", startDay, endDay)
	}

	updateChan := make(chan *gluePartitionUpdate, concurrency)

	// delete and re-create concurrently cuz the Glue API is very slow
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			for update := range updateChan {
				_, err := update.table.DeletePartition(glueClient, update.at)
				if err != nil {
					if awsErr, ok := err.(awserr.Error); ok {
						if awsErr.Code() != "EntityNotFoundException" { // don't fail if partition is not there
							fmt.Printf("delete partition for %s at %v failed: %s\n", update.table.TableName(), update.at, err)
							continue
						}
					}
				}
				err = update.table.CreateJSONPartition(glueClient, update.at)
				if err != nil {
					fmt.Printf("create partition for %s at %v failed: %s\n", update.table.TableName(), update.at, err)
				}
			}
			wg.Done()
		}()
	}

	// for each table, for each time partition, delete and re-create
	for _, table := range registry.AvailableTables() {
		name := fmt.Sprintf("%s.%s", table.DatabaseName(), table.TableName())
		if len(matchTableName) > 0 && !strings.Contains(name, matchTableName) {
			continue
		}
		fmt.Printf("sync'ing %s\n", name)
		for timeBin := startDay; !timeBin.After(endDay); timeBin = table.Timebin().Next(timeBin) {
			updateChan <- &gluePartitionUpdate{
				table: table,
				at:    timeBin,
			}
		}
	}

	close(updateChan)
	wg.Wait()

	return nil
}

type gluePartitionUpdate struct {
	table *awsglue.GlueMetadata
	at    time.Time
}
