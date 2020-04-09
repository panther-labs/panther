package gatewayapi

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
