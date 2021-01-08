// Code generated by apigen; DO NOT EDIT.
package logtypesapi

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
	"encoding/json"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
)

// LogTypesAPILambdaClient implements LogTypesAPI by invoking a Lambda
type LogTypesAPILambdaClient struct {
	LambdaName string
	LambdaAPI  lambdaiface.LambdaAPI
	Validate   func(interface{}) error
	JSON       jsoniter.API
}

type LogTypesAPIPayload struct {
	ListAvailableLogTypes *struct{}          `json:"ListAvailableLogTypes,omitempty"`
	GetCustomLog          *GetCustomLogInput `json:"GetCustomLog,omitempty"`
	PutCustomLog          *PutCustomLogInput `json:"PutCustomLog,omitempty"`
	DelCustomLog          *DelCustomLogInput `json:"DelCustomLog,omitempty"`
	ListCustomLogs        *struct{}          `json:"ListCustomLogs,omitempty"`
}

func (c *LogTypesAPILambdaClient) ListAvailableLogTypes(ctx context.Context) (*AvailableLogTypes, error) {
	payload := LogTypesAPIPayload{
		ListAvailableLogTypes: &struct{}{},
	}
	reply := AvailableLogTypes{}
	if err := c.invoke(ctx, &payload, &reply); err != nil {
		return nil, err
	}
	return &reply, nil
}

func (c *LogTypesAPILambdaClient) GetCustomLog(ctx context.Context, input *GetCustomLogInput) (*GetCustomLogOutput, error) {
	if input == nil {
		input = &GetCustomLogInput{}
	}
	payload := LogTypesAPIPayload{
		GetCustomLog: input,
	}
	reply := GetCustomLogOutput{}
	if err := c.invoke(ctx, &payload, &reply); err != nil {
		return nil, err
	}
	return &reply, nil
}

func (c *LogTypesAPILambdaClient) PutCustomLog(ctx context.Context, input *PutCustomLogInput) (*PutCustomLogOutput, error) {
	if input == nil {
		input = &PutCustomLogInput{}
	}
	payload := LogTypesAPIPayload{
		PutCustomLog: input,
	}
	reply := PutCustomLogOutput{}
	if err := c.invoke(ctx, &payload, &reply); err != nil {
		return nil, err
	}
	return &reply, nil
}

func (c *LogTypesAPILambdaClient) DelCustomLog(ctx context.Context, input *DelCustomLogInput) (*DelCustomLogOutput, error) {
	if input == nil {
		input = &DelCustomLogInput{}
	}
	payload := LogTypesAPIPayload{
		DelCustomLog: input,
	}
	reply := DelCustomLogOutput{}
	if err := c.invoke(ctx, &payload, &reply); err != nil {
		return nil, err
	}
	return &reply, nil
}

func (c *LogTypesAPILambdaClient) ListCustomLogs(ctx context.Context) (*ListCustomLogsOutput, error) {
	payload := LogTypesAPIPayload{
		ListCustomLogs: &struct{}{},
	}
	reply := ListCustomLogsOutput{}
	if err := c.invoke(ctx, &payload, &reply); err != nil {
		return nil, err
	}
	return &reply, nil
}

func (c *LogTypesAPILambdaClient) invoke(ctx context.Context, payload, reply interface{}) error {
	if validate := c.Validate; validate != nil {
		if err := validate(payload); err != nil {
			return err
		}
	}
	marshal := json.Marshal
	if c.JSON != nil {
		marshal = c.JSON.Marshal
	}
	payloadJSON, err := marshal(payload)
	if err != nil {
		return err
	}
	output, err := c.LambdaAPI.InvokeWithContext(ctx, &lambda.InvokeInput{
		FunctionName: aws.String(c.LambdaName),
		Payload:      payloadJSON,
	})
	if err != nil {
		return err
	}
	unmarshal := json.Unmarshal
	if c.JSON != nil {
		unmarshal = c.JSON.Unmarshal
	}
	if output.FunctionError != nil {
		invokeErr := struct {
			Message string "json:\"errorMessage\""
		}{}
		if err := unmarshal(output.Payload, &invokeErr); err != nil {
			return err
		}
		return errors.Errorf("lambda %q execution failed: %s", c.LambdaName, invokeErr.Message)
	}
	if reply == nil {
		return nil
	}
	return unmarshal(output.Payload, reply)
}
