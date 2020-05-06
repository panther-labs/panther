package main

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

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-lambda-go/lambda"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/core/custom_resources/resources"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

// Returns physicalResourceID and outputs
func customResourceHandler(ctx context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	_, logger := lambdalogger.ConfigureGlobal(ctx, map[string]interface{}{
		"requestType":        event.RequestType,
		"resourceType":       event.ResourceType,
		"physicalResourceId": event.PhysicalResourceID,
	})
	logger.Info("received custom resource request", zap.Any("event", event))

	handler, ok := resources.CustomResources[event.ResourceType]
	if !ok {
		return "", nil, fmt.Errorf("unsupported resource type: %s", event.ResourceType)
	}

	return handler(ctx, event)
}

func main() {
	lambda.Start(cfn.LambdaWrap(customResourceHandler))
}
