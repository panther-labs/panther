package logtypesapi

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import (
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

const (
	recordKindStatus      = "status"
	attrAvailableLogTypes = "AvailableLogTypes"
)

type AvailableLogTypes struct {
	LogTypes []string `json:"logTypes"`
}

func (api *API) ListAvailableLogTypes(ctx context.Context) (*AvailableLogTypes, error) {
	ddbInput := dynamodb.GetItemInput{
		TableName:            aws.String(api.TableName),
		ProjectionExpression: aws.String(attrAvailableLogTypes),
		Key: mustMarshalMap(&recordKey{
			RecordID:   "Status",
			RecordKind: recordKindStatus,
		}),
	}
	ddbOutput, err := api.DB.GetItemWithContext(ctx, &ddbInput)
	if err != nil {
		return nil, err
	}
	logTypes := aws.StringValueSlice(ddbOutput.Item[attrAvailableLogTypes].SS)

	logTypes = append(logTypes, api.NativeLogTypes.LogTypes()...)

	return &AvailableLogTypes{
		LogTypes: logTypes,
	}, nil
}
