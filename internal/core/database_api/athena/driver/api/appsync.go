package api

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
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/database/models"
)

// FIXME: consider adding as stand-alone lambda to de-couple this from Athena api

func (API) NotifyAppSync(input *models.NotifyAppSyncInput) (*models.NotifyAppSyncOutput, error) {
	output := &models.NotifyAppSyncOutput{}

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}
	}()

	// FIXME: this is unfinished, don't bother looking

	// make sigv4 https request to appsync endpoint notifying query is complete, sending  queryId and workflowId
	appSyncEndpoint := os.Getenv("GRAPHQL_ENDPOINT")
	httpClient := http.Client{}
	signer := v4.NewSigner(awsSession.Config.Credentials)

	// FIXME: needs to be an agreed on mutation to trigger a subscription
	body := strings.NewReader(fmt.Sprintf(`{ "queryId": "%s", workflowId": "%s"}`,
		input.QueryID, input.WorkflowID))

	req, err := http.NewRequest("POST", appSyncEndpoint, body)
	if err != nil {
		err = errors.Wrapf(err, "new htttp request failed for: %#v", input)
		return output, err
	}
	req.Header.Add("Content-Type", "application/json")

	if awsSession.Config.Region == nil {
		err = errors.Wrapf(err, "failed to get aws region %#v", input)
		return output, err
	}

	_, err = signer.Sign(req, body, "states", *awsSession.Config.Region, time.Now().UTC())
	if err != nil {
		err = errors.Wrapf(err, "failed to v4 sign %#v", input)
		return output, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		err = errors.Wrapf(err, "failed to POST %#v", req)
		return output, err
	}
	defer resp.Body.Close()

	respBody, _ := ioutil.ReadAll(resp.Body)
	zap.L().Error("NotifyAppSync I/O",
		zap.Any("respCode", resp.StatusCode),
		zap.Any("respBody", string(respBody)))

	if resp.StatusCode != 200 {
		zap.L().Error("NotifyAppSync NOT 200")
		err = errors.Wrapf(err, "failed to POST %#v: %#v", req, resp)
		return output, err
	}

	return output, nil
}
