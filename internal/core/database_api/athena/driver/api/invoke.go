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

	"github.com/aws/aws-sdk-go/service/lambda"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/database/models"
)

// called by Step workflow to execute callback the query that ran
func (API) InvokeNotifyLambda(input *models.InvokeNotifyLambdaInput) (*models.InvokeNotifyLambdaInput, error) {
	output := &models.InvokeNotifyLambdaInput{}

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}
	}()

	// these lambdas are expected to take QueryID in as argument, then execute a callback to get results/continue
	queryIDJSON, err := jsoniter.Marshal(&input.GetQueryStatusInput)
	if err != nil {
		return output, errors.Wrapf(err, "failed to marshal %#v", input.GetQueryStatusInput)
	}

	payload := []byte(fmt.Sprintf("%s %s", input.MethodName, string(queryIDJSON)))
	_, err = lambdaClient.Invoke(&lambda.InvokeInput{
		FunctionName: &input.LambdaName,
		Payload:      payload,
	})

	return output, errors.Wrapf(err, "failed to invoke %#v", input)
}
