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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"

	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
)

func createAlertOutput() *outputModels.AlertOutput {
	return &outputModels.AlertOutput{
		CreatedBy:          aws.String("userId"),
		CreationTime:       aws.String(time.Now().Local().String()),
		DefaultForSeverity: []*string{aws.String("INFO"), aws.String("CRITICAL")},
		DisplayName:        aws.String("slack:alerts"),
		LastModifiedBy:     aws.String("userId"),
		LastModifiedTime:   aws.String(time.Now().Local().String()),
		OutputID:           aws.String("outputId"),
		OutputType:         aws.String("slack"),
		OutputConfig: &outputModels.OutputConfig{
			Slack: &outputModels.SlackConfig{
				WebhookURL: "https://slack.com",
			},
		},
	}
}

func createAlertOutputs() []*outputModels.AlertOutput {
	return []*outputModels.AlertOutput{createAlertOutput(), createAlertOutput(), createAlertOutput()}
}

// By default, cache.get() will initialize the cache - no need
// to explicitly call cache.set(...)
//
// To override the default action, the user must cache.get()
// then cache.set(nil) in order to successfully set the cache
// to nil. This is for debugging/testing and should not be
// used in application.
func TestGetSetCache(t *testing.T) {
	assert.Nil(t, cache)
	c := &outputsCache{}

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
	assert.NotNil(t, cache)
	assert.Equal(t, cPtr, cache)
	assert.Equal(t, cPtr.get(), cache.get())
}

func TestGetSetOutputs(t *testing.T) {
	c := &outputsCache{}
	outputs := createAlertOutputs()
	c.setOutputs(outputs)
	assert.Equal(t, outputs, c.getOutputs())
	assert.Equal(t, c.getOutputs(), cache.getOutputs())
}

func TestGetSetExpiry(t *testing.T) {
	c := &outputsCache{}
	expiry := time.Now().Add(time.Second * time.Duration(10))
	c.setExpiry(expiry)
	assert.Equal(t, expiry, c.getExpiry())
	assert.Equal(t, c.getExpiry(), cache.getExpiry())
}

func TestIsNotExpired(t *testing.T) {
	c := &outputsCache{}
	expiry := time.Now().Add(time.Second * time.Duration(-29))
	c.setExpiry(expiry)
	assert.False(t, c.isExpired())
	assert.Equal(t, c.isExpired(), cache.isExpired())
}
func TestIsExpired(t *testing.T) {
	c := &outputsCache{}
	expiry := time.Now().Add(time.Second * time.Duration(-30))
	c.setExpiry(expiry)
	assert.True(t, c.isExpired())
	assert.Equal(t, c.isExpired(), cache.isExpired())
}

func TestIsExpiredByDefault(t *testing.T) {
	c := &outputsCache{}
	assert.True(t, c.isExpired())
	assert.Equal(t, c.isExpired(), cache.isExpired())
}
