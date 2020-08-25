package logtypesapi

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
