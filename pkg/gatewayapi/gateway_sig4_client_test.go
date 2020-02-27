package gatewayapi

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
	"bytes"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSig4ClientDefault(t *testing.T) {
	require.NoError(t, os.Setenv("AWS_ACCESS_KEY_ID", "Panther"))
	require.NoError(t, os.Setenv("AWS_SECRET_ACCESS_KEY", "Labs"))
	c := GatewayClient(session.Must(session.NewSession(nil)))
	assert.NotNil(t, c)
}

func TestSig4ClientMissingPathParameters(t *testing.T) {
	require.NoError(t, os.Setenv("AWS_ACCESS_KEY_ID", "Panther"))
	require.NoError(t, os.Setenv("AWS_SECRET_ACCESS_KEY", "Labs"))
	c := GatewayClient(session.Must(session.NewSession(nil)))
	result, err := c.Get("https://example.com/path//missing")
	require.Error(t, err)
	assert.True(t, strings.HasSuffix(err.Error(), "sig4: missing path parameter"))
	assert.Nil(t, result)
}

type validateTransport struct {
	sentHeaders http.Header
	sentBody    []byte
}

func (t *validateTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.sentHeaders = r.Header
	t.sentBody, _ = ioutil.ReadAll(r.Body)
	return &http.Response{}, nil
}

func TestSig4ClientSignature(t *testing.T) {
	require.NoError(t, os.Setenv("AWS_ACCESS_KEY_ID", "Panther"))
	require.NoError(t, os.Setenv("AWS_SECRET_ACCESS_KEY", "Labs"))
	require.NoError(t, os.Setenv("AWS_REGION", "us-west-2"))
	validator := &validateTransport{}
	config := aws.NewConfig().
		WithCredentials(credentials.NewEnvCredentials()).
		WithRegion("us-west-2").
		WithHTTPClient(&http.Client{Transport: validator})
	awsSession := session.Must(session.NewSession(config))
	httpClient := GatewayClient(awsSession)

	assert.Empty(t, validator.sentHeaders)
	result, err := httpClient.Post(
		"https://runpanther.io",
		"application/json",
		bytes.NewReader([]byte("Panther Labs")),
	)
	require.NoError(t, err)
	require.NotNil(t, result)

	// An Authorization header should have been added
	_, authExists := validator.sentHeaders["Authorization"]
	assert.True(t, authExists)
	assert.Equal(t, []byte("Panther Labs"), validator.sentBody)
}
