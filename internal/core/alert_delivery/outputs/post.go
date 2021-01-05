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
	"context"
	"io/ioutil"
	"net/http"

	jsoniter "github.com/json-iterator/go"
)

const (
	AuthorizationHTTPHeader = "Authorization"
)

// post sends a JSON body to an endpoint.
func (client *HTTPWrapper) post(ctx context.Context, input *PostInput) *AlertDeliveryResponse {
	payload, err := jsoniter.Marshal(input.body)

	// If there was an error marshaling the input
	if err != nil {
		return &AlertDeliveryResponse{
			StatusCode: 500, // Internal server error
			Success:    false,
			Message:    "json marshal error: " + err.Error(),
			Permanent:  true,
		}
	}

	request, err := http.NewRequestWithContext(ctx, "POST", input.url, bytes.NewBuffer(payload))

	// If there was an error creating the request
	if err != nil {
		return &AlertDeliveryResponse{
			StatusCode: 500, // Internal server error
			Success:    false,
			Message:    "http request error: " + err.Error(),
			Permanent:  true,
		}
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	//Adding dynamic headers
	for key, value := range input.headers {
		request.Header.Set(key, value)
	}

	response, err := client.httpClient.Do(request)

	// If there was an error sending the request
	if err != nil {
		return &AlertDeliveryResponse{
			StatusCode: 500, // Internal server error
			Success:    false,
			Message:    "network error: " + err.Error(),
			Permanent:  false,
		}
	}

	defer response.Body.Close()

	body, _ := ioutil.ReadAll(response.Body)

	// If the client response status code is not acceptable
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return &AlertDeliveryResponse{
			StatusCode: response.StatusCode,
			Success:    false,
			Message:    "request failed: " + response.Status + ": " + string(body),
			Permanent:  false,
		}
	}

	return &AlertDeliveryResponse{
		StatusCode: response.StatusCode,
		Success:    true,
		Message:    string(body),
		Permanent:  false,
	}
}
