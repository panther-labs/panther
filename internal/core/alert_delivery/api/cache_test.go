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

func TestGetSetCache(t *testing.T) {
	assert.Nil(t, outputsCache)
	c := &alertOutputsCache{}

	cPtr := c.get()
	assert.Nil(t, cPtr)
	assert.Nil(t, outputsCache)

	c.set(nil)
	cPtr = c.get()
	assert.Nil(t, cPtr)
	assert.Nil(t, outputsCache)

	c.set(&alertOutputsCache{})
	cPtr = c.get()
	assert.NotNil(t, cPtr)
	assert.NotNil(t, outputsCache)
	assert.Equal(t, cPtr, outputsCache)
	assert.Equal(t, cPtr.get(), outputsCache.get())
}

func TestGetSetOutputs(t *testing.T) {
	outputsCache = &alertOutputsCache{}
	c := outputsCache.get()
	outputs := createAlertOutputs()
	c.setOutputs(outputs)
	assert.Equal(t, outputs, c.getOutputs())
	assert.Equal(t, c.getOutputs(), outputsCache.getOutputs())
}

func TestGetSetExpiry(t *testing.T) {
	outputsCache = &alertOutputsCache{}
	c := outputsCache.get()
	expiry := time.Now().Add(time.Second * time.Duration(10))
	c.setExpiry(expiry)
	assert.Equal(t, expiry, c.getExpiry())
	assert.Equal(t, c.getExpiry(), outputsCache.getExpiry())
}

func TestIsNotExpired(t *testing.T) {
	outputsCache = &alertOutputsCache{}
	c := outputsCache.get()
	c.setRefreshInterval(time.Second * time.Duration(30))
	c.setExpiry(time.Now().Add(time.Second * time.Duration(-29)))
	assert.False(t, c.isExpired())
}
func TestIsExpired(t *testing.T) {
	outputsCache = &alertOutputsCache{}
	c := outputsCache.get()
	c.setRefreshInterval(time.Second * time.Duration(30))
	c.setExpiry(time.Now().Add(time.Second * time.Duration(-30)))
	assert.True(t, c.isExpired())
}
