// Package api defines CRUD actions for the Panther alerts database.
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
	"encoding/base64"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	jsoniter "github.com/json-iterator/go"
	"github.com/kelseyhightower/envconfig"

	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
)

// API has all of the handlers as receiver methods.
type API struct{}

var (
	env        envConfig
	awsSession *session.Session
	alertsDB   table.API
	glueClient glueiface.GlueAPI
	s3Client   s3iface.S3API
)

type envConfig struct {
	AnalysisAPIHost     string `required:"true" split_words:"true"`
	AnalysisAPIPath     string `required:"true" split_words:"true"`
	AlertsTableName     string `required:"true" split_words:"true"`
	RuleIndexName       string `required:"true" split_words:"true"`
	TimeIndexName       string `required:"true" split_words:"true"`
	ProcessedDataBucket string `required:"true" split_words:"true"`
}

// Setup parses the environment and builds the AWS and http clients.
func Setup() {
	envconfig.MustProcess("", &env)

	awsSession = session.Must(session.NewSession())
	alertsDB = &table.AlertsTable{
		AlertsTableName:                    env.AlertsTableName,
		Client:                             dynamodb.New(awsSession),
		RuleIDCreationTimeIndexName:        env.RuleIndexName,
		TimePartitionCreationTimeIndexName: env.TimeIndexName,
	}
	glueClient = glue.New(awsSession)
	s3Client = s3.New(awsSession)
}

type paginationToken struct {
	logTypeToLastEvent map[string]*lastObjectProcessed
}

type lastObjectProcessed struct {
	key       string
	eventIndex int
}

func newPaginationToken() *paginationToken {
	return &paginationToken{logTypeToLastEvent: make(map[string]*lastObjectProcessed)}
}

func (pt *paginationToken) encode() (string, error) {
	marshalled, err := jsoniter.Marshal(pt)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(marshalled), nil
}

func decodePaginationToken(token string) (*paginationToken, error) {
	unmarshalled, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}
	result := &paginationToken{}
	if err = jsoniter.Unmarshal(unmarshalled, result); err != nil {
		return nil, err
	}
	return result, nil
}
