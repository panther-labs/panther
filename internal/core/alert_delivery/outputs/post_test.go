package outputs

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
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockHTTPClient struct {
	HTTPiface
	statusCode   int
	requestError bool
	requestBody  string // Request body is saved here for tests to verify
}

var requestEndpoint = "https://runpanther.io"

func (m *mockHTTPClient) Do(request *http.Request) (*http.Response, error) {
	if m.requestError {
		return nil, errors.New("endpoint unreachable")
	}
	requestBytes, err := ioutil.ReadAll(request.Body)
	if err != nil {
		panic(err)
	}
	m.requestBody = string(requestBytes)

	responseBody := ioutil.NopCloser(bytes.NewReader([]byte("response")))
	return &http.Response{Body: responseBody, StatusCode: m.statusCode}, nil
}

func TestPostInvalidJSON(t *testing.T) {
	body := map[string]interface{}{"func": TestPostInvalidJSON}
	postInput := &PostInput{
		url:  requestEndpoint,
		body: body,
	}
	c := &HTTPWrapper{httpClient: &mockHTTPClient{}}
	assert.NotNil(t, c.post(postInput))
}

func TestPostErrorSubmittingRequest(t *testing.T) {
	c := &HTTPWrapper{httpClient: &mockHTTPClient{requestError: true}}
	postInput := &PostInput{
		url:  requestEndpoint,
		body: map[string]interface{}{"abc": 123},
	}
	assert.NotNil(t, c.post(postInput))
}

func TestPostNotOk(t *testing.T) {
	c := &HTTPWrapper{httpClient: &mockHTTPClient{statusCode: http.StatusBadRequest}}
	postInput := &PostInput{
		url:  requestEndpoint,
		body: map[string]interface{}{"abc": 123},
	}
	assert.NotNil(t, c.post(postInput))
}

func TestPostOk(t *testing.T) {
	c := &HTTPWrapper{httpClient: &mockHTTPClient{statusCode: http.StatusOK}}
	postInput := &PostInput{
		url:  requestEndpoint,
		body: map[string]interface{}{"abc": 123},
	}
	assert.Nil(t, c.post(postInput))
}

func TestPostCreated(t *testing.T) {
	c := &HTTPWrapper{httpClient: &mockHTTPClient{statusCode: http.StatusCreated}}
	postInput := &PostInput{
		url:  requestEndpoint,
		body: map[string]interface{}{"abc": 123},
	}
	assert.Nil(t, c.post(postInput))
}
