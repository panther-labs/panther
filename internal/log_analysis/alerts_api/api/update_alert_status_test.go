package api

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
	"fmt"
	"math"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
)

func TestUpdateAlert(t *testing.T) {
	tableMock := &tableMock{}
	alertsDB = tableMock

	status := aws.String("OPEN")
	userID := aws.String("userId")
	timeNow := time.Now()
	input := &models.UpdateAlertStatusInput{
		AlertIDs: []*string{},
		Status:   status,
		UserID:   userID,
	}

	output := []*table.AlertItem{}
	expectedSummaries := []*models.AlertSummary{}

	// Set the default ddb page size
	maxDDBPageSize = uint64(25)

	// Set the total number of alerts to generate
	alertCount := uint64(12345)
	for i := uint64(0); i < alertCount; i++ {
		alertID := fmt.Sprint(i) // make the alertID a number for easier sorting
		input.AlertIDs = append(input.AlertIDs, aws.String(alertID))
		output = append(output, &table.AlertItem{
			AlertID:           alertID,
			Status:            "CLOSED",
			Severity:          "INFO",
			LastUpdatedBy:     *userID,
			LastUpdatedByTime: timeNow,
			DeliveryResponses: []*models.DeliveryResponse{},
			CreationTime:      timeNow,
			UpdateTime:        timeNow,
		})
		expectedSummaries = append(expectedSummaries, &models.AlertSummary{
			AlertID:           aws.String(alertID),
			RuleID:            aws.String(""),
			RuleVersion:       aws.String(""),
			RuleDisplayName:   nil,
			DedupString:       aws.String(""),
			LogTypes:          []string{},
			Severity:          aws.String("INFO"),
			Status:            "CLOSED",
			LastUpdatedBy:     *userID,
			LastUpdatedByTime: timeNow,
			DeliveryResponses: []*models.DeliveryResponse{},
			CreationTime:      aws.Time(timeNow),
			UpdateTime:        aws.Time(timeNow),
			EventsMatched:     aws.Int(0),
			Title:             aws.String(""),
		})
	}

	pages := uint64(math.Ceil(float64(alertCount) / float64(maxDDBPageSize)))

	// We need to mimic the mock's true payload as it will happen in chunks
	for page := uint64(0); page < pages; page++ {
		pageSize := uint64(math.Min(float64((page*maxDDBPageSize)+maxDDBPageSize), float64(alertCount)))
		tableMock.On("UpdateAlertStatus", mock.Anything).Return(output[page*maxDDBPageSize:pageSize], nil).Once()
	}

	results, err := API{}.UpdateAlertStatus(input)
	require.NoError(t, err)

	// The results will sometimes be out-of-order due to the concurrency
	// We sort them here to compare against the original set
	sort.Slice(results, func(i, j int) bool {
		ID1, _ := strconv.Atoi(*results[i].AlertID)
		ID2, _ := strconv.Atoi(*results[j].AlertID)
		return ID1 < ID2
	})

	assert.Equal(t, expectedSummaries, results)
}
