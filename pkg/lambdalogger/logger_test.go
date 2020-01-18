package lambdalogger

/**
 * Copyright 2020 Panther Labs Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
