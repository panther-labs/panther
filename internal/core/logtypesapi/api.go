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
	session "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
)

// Generate a lambda client using genlambdamux
//go:generate go run github.com/panther-labs/panther/pkg/lambdamux/genlambdamux -out ./apiclient_gen.go

type Config struct {
	LogTypesTableName string `required:"true" split_words:"true"`
}

type API struct {
	NativeLogTypes *logtypes.Registry
	DB             dynamodbiface.DynamoDBAPI
	TableName      string
}

func BuildAPI(config *Config) *API {
	awsSession := session.Must(session.NewSession())
	db := dynamodb.New(awsSession)
	return &API{
		NativeLogTypes: registry.Default(),
		DB:             db,
		TableName:      config.LogTypesTableName,
	}
}
