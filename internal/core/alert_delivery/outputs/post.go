package outputs

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

	jsoniter "github.com/json-iterator/go"
)

const (
	AuthorizationHTTPHeader = "Authorization"
)

// post sends a JSON body to an endpoint.
func (client *HTTPWrapper) post(input *PostInput) *AlertDeliveryError {
	payload, err := jsoniter.Marshal(input.body)
	if err != nil {
		return &AlertDeliveryError{Message: "json marshal error: " + err.Error(), Permanent: true}
	}

	request, err := http.NewRequest("POST", input.url, bytes.NewBuffer(payload))
	if err != nil {
		return &AlertDeliveryError{Message: "http request error: " + err.Error(), Permanent: true}
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	//Adding dynamic headers
	for key, value := range input.headers {
		request.Header.Set(key, value)
	}

	response, err := client.httpClient.Do(request)
	if err != nil {
		return &AlertDeliveryError{Message: "network error: " + err.Error()}
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode > 299 {
		body, _ := ioutil.ReadAll(response.Body)
		return &AlertDeliveryError{
			Message: "request failed: " + response.Status + ": " + string(body)}
	}

	return nil
}
