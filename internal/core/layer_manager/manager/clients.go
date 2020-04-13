package manager

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
	"os"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"

	analysisapi "github.com/panther-labs/panther/api/gateway/analysis/client"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

var (
	analysisServiceHost = os.Getenv("ANALYSIS_API_HOST")
	analysisServicePath = os.Getenv("ANALYSIS_API_PATH")

	awsSession     = session.Must(session.NewSession())
	httpClient     = gatewayapi.GatewayClient(awsSession)
	analysisConfig = analysisapi.DefaultTransportConfig().
			WithHost(analysisServiceHost).
			WithBasePath(analysisServicePath)

	// We will always need the Lambda client (to get output details)
	lambdaClient   lambdaiface.LambdaAPI = lambda.New(awsSession)
	analysisClient                       = analysisapi.NewHTTPClientWithConfig(nil, analysisConfig)
)
