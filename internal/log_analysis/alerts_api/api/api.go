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
	"net/http"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/kelseyhightower/envconfig"

	"github.com/panther-labs/panther/api/gateway/analysis/client"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// API has all of the handlers as receiver methods.
type API struct{}

var (
	env            envConfig
	awsSession     *session.Session
	httpClient     *http.Client
	policiesClient *client.PantherAnalysis
	alertsDB       table.API
)

type envConfig struct {
	AnalysisAPIHost string `required:"true" split_words:"true"`
	AnalysisAPIPath string `required:"true" split_words:"true"`
	AlertsTableName string `required:"true" split_words:"true"`
	RuleIndexName   string `required:"true" split_words:"true"`
	EventsTableName string `required:"true" split_words:"true"`
}

// Setup parses the environment and builds the AWS and http clients.
func Setup() {
	envconfig.MustProcess("", &env)

	awsSession = session.Must(session.NewSession())

	httpClient = gatewayapi.GatewayClient(awsSession)
	policiesClient = client.NewHTTPClientWithConfig(
		nil, client.DefaultTransportConfig().
			WithHost(env.AnalysisAPIHost).
			WithBasePath("/"+env.AnalysisAPIPath))

	alertsDB = &table.AlertsTable{
		AlertsTableName:             env.AlertsTableName,
		Client:                      dynamodb.New(awsSession),
		EventsTableName:             env.EventsTableName,
		RuleIDCreationTimeIndexName: env.RuleIndexName,
	}
}
