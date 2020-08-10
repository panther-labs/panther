package delivery

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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/panther-labs/panther/internal/core/alert_delivery/outputs"
)

func TestMustParseIntPanic(t *testing.T) {
	assert.Panics(t, func() { mustParseInt("") })
}

func TestHandleAlertsPermanentlyFailed(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient
	mockClient.On("Slack", mock.Anything, mock.Anything).Return(&outputs.AlertDeliveryResponse{})
	sqsClient = &mockSQSClient{}
	setCaches()
	os.Setenv("ALERT_RETRY_COUNT", "0") // set '0' to branch immediately
	os.Setenv("ALERT_QUEUE_URL", "sqs.url")
	os.Setenv("MIN_RETRY_DELAY_SECS", "10")
	os.Setenv("MAX_RETRY_DELAY_SECS", "30")
	alert := sampleAlert()
	alerts := []*models.Alert{alert, alert, alert}
	sqsMessages = 0

	HandleAlerts(alerts)
	assert.Equal(t, 0, sqsMessages)
}

func TestHandleAlertsTemporarilyFailed(t *testing.T) {
	mockClient := &mockOutputsClient{}
	outputClient = mockClient
	mockClient.On("Slack", mock.Anything, mock.Anything).Return(&outputs.AlertDeliveryResponse{})
	sqsClient = &mockSQSClient{}
	setCaches()
	os.Setenv("ALERT_RETRY_COUNT", "10")
	os.Setenv("ALERT_QUEUE_URL", "sqs.url")
	os.Setenv("MIN_RETRY_DELAY_SECS", "10")
	os.Setenv("MAX_RETRY_DELAY_SECS", "30")
	alert := sampleAlert()
	alerts := []*models.Alert{alert, alert, alert}
	sqsMessages = 0

	HandleAlerts(alerts)
	assert.Equal(t, 3, sqsMessages)
}
