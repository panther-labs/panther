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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
)

func createAlertOutput() *outputmodels.AlertOutput {
	return &outputmodels.AlertOutput{
		CreatedBy:          aws.String("userId"),
		CreationTime:       aws.String(time.Now().Local().String()),
		DefaultForSeverity: []*string{aws.String("INFO"), aws.String("CRITICAL")},
		DisplayName:        aws.String("slack:alerts"),
		LastModifiedBy:     aws.String("userId"),
		LastModifiedTime:   aws.String(time.Now().Local().String()),
		OutputID:           aws.String("outputId"),
		OutputType:         aws.String("slack"),
		OutputConfig: &outputmodels.OutputConfig{
			Slack: &outputmodels.SlackConfig{
				WebhookURL: "https://slack.com",
			},
		},
	}
}

func createAlertOutputs() []*outputmodels.AlertOutput {
	return []*outputmodels.AlertOutput{createAlertOutput(), createAlertOutput(), createAlertOutput()}
}

// By default, a cache should never return nil unless it is intentional
func TestGet(t *testing.T) {
	c := &outputsCache{}
	assert.NotNil(t, c.get())
}

// To override the default action, the user must cache.get()
// then cache.set(nil) in order to successfully set the cache
// to nil. This is for debugging/testing and should not be
// directly used in application.
func TestSetNil(t *testing.T) {
	c := &outputsCache{}
	assert.Equal(t, c, cache)

	cPtr := c.get()
	assert.NotNil(t, cPtr)
	assert.NotNil(t, cache)

	c.set(nil)
	cPtr = c.get()
	assert.Nil(t, cPtr)
	assert.Nil(t, cache)

	c.set(&outputsCache{})
	cPtr = c.get()
	assert.NotNil(t, cPtr)
	assert.Equal(t, c.get(), cache.get())
}

func TestGetOutputs(t *testing.T) {
	c := &outputsCache{}
	outputs := createAlertOutputs()
	c.setOutputs(outputs)
	assert.Equal(t, outputs, c.getOutputs())
	assert.Equal(t, c.getOutputs(), cache.getOutputs())
}
func TestSetOutputs(t *testing.T) {
	c := &outputsCache{}
	outputs := createAlertOutputs()
	c.setOutputs(outputs)
	assert.Equal(t, outputs, c.getOutputs())
	assert.Equal(t, c.getOutputs(), cache.getOutputs())
}

func TestGetExpiry(t *testing.T) {
	c := &outputsCache{}
	expiry := time.Now()
	c.setExpiry(expiry)
	assert.Equal(t, expiry, c.getExpiry())
	assert.Equal(t, c.getExpiry(), cache.getExpiry())
}
func TestSetExpiry(t *testing.T) {
	c := &outputsCache{}
	expiry := time.Now().Add(time.Second * time.Duration(10))
	c.setExpiry(expiry)
	assert.Equal(t, c.getExpiry(), cache.getExpiry())
}

func TestIsNotExpired(t *testing.T) {
	c := &outputsCache{}
	expiry := time.Now().Add(time.Second * time.Duration(-5*59))
	c.setExpiry(expiry)
	assert.False(t, c.isExpired())
	assert.Equal(t, c.isExpired(), cache.isExpired())
}
func TestIsExpired(t *testing.T) {
	c := &outputsCache{}
	expiry := time.Now().Add(time.Second * time.Duration(-5*60))
	c.setExpiry(expiry)
	assert.True(t, c.isExpired())
	assert.Equal(t, c.isExpired(), cache.isExpired())
}
