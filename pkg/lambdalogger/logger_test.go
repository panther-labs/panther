package lambdalogger

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"context"
	"testing"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/stretchr/testify/assert"
)

var testContext = lambdacontext.NewContext(
	context.Background(), &lambdacontext.LambdaContext{AwsRequestID: "test-request-id"})

func TestConfigureGlobalDebug(t *testing.T) {
	DebugEnabled = true
	lc, logger := ConfigureGlobal(testContext, nil)
	assert.NotNil(t, lc)
	assert.NotNil(t, logger)
}

func TestConfigureGlobalProd(t *testing.T) {
	DebugEnabled = false
	lc, logger := ConfigureGlobal(testContext, nil)
	assert.NotNil(t, lc)
	assert.NotNil(t, logger)
}

func TestConfigureExtraFields(t *testing.T) {
	lc, logger := ConfigureGlobal(testContext, map[string]interface{}{"panther": "labs"})
	assert.NotNil(t, lc)
	assert.NotNil(t, logger)
}

func TestConfigureGlobalError(t *testing.T) {
	assert.Panics(t, func() { ConfigureGlobal(context.Background(), nil) })
}
