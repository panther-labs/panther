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
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
)

// GatewayClient generates an http client that can invoke API Gateway endpoints with AWS_IAM authentication.
func GatewayClient(s *session.Session) *http.Client {
	return &http.Client{
		Transport: &gatewayTransport{
			httpClient: s.Config.HTTPClient,
			region:     aws.StringValue(s.Config.Region),
			signer:     v4.NewSigner(s.Config.Credentials),
		},
	}
}

type gatewayTransport struct {
	httpClient *http.Client
	region     string
	signer     *v4.Signer
}

// RoundTrip replaces every http.Request with an AWS-signed request before sending it.
func (transport *gatewayTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.Contains(r.URL.Path, "//") {
		// Empty path parameters will result in a double backslash and a signature failure.
		//
		// For example, "GET /orgs/{orgId}/accounts" will become "GET /orgs//accounts" if orgId is not specified.
		// The canonical request becomes "GET /orgs/accounts", which causes the signature mis-match.
		// We could replace consecutive backslashes with a single backslash to fix the signature,
		// but this is almost certainly a missing path parameter, so we might as well error here.
		return nil, errors.New("sig4: missing path parameter")
	}

	// RoundTrip is not allowed to modify the request, so we make a new one instead.
	// (See the RoundTripper interface in https://golang.org/src/net/http/client.go)
	newRequest, err := http.NewRequest(r.Method, r.URL.String(), nil)
	if err != nil {
		return nil, err
	}

	newRequest.Header = r.Header

	// If there is a body, copy it from a ReadCloser into a ReadSeeker.
	var newBody io.ReadSeeker
	if r.Body != nil {
		oldBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		newBody = bytes.NewReader(oldBody)
	}

	_, err = transport.signer.Sign(newRequest, newBody, "execute-api", transport.region, time.Now())
	if err != nil {
		return nil, err
	}

	return transport.httpClient.Do(newRequest)
}
