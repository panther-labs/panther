package outputs

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

	jsoniter "github.com/json-iterator/go"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
)

const (
	OpsgenieServiceRegionUS = "US"
	OpsgenieServiceRegionEU = "EU"
)

var pantherToOpsGeniePriority = map[string]string{
	"CRITICAL": "P1",
	"HIGH":     "P2",
	"MEDIUM":   "P3",
	"LOW":      "P4",
	"INFO":     "P5",
}

// Opsgenie alert send an alert.
func (client *OutputClient) Opsgenie(
	ctx context.Context, alert *deliverymodel.Alert, config *outputModels.OpsgenieConfig) *AlertDeliveryResponse {

	description := "<strong>Description:</strong> " + alert.AnalysisDescription
	link := "\n<a href=\"" + generateURL(alert) + "\">Click here to view in the Panther UI</a>"
	runBook := "\n <strong>Runbook:</strong> " + alert.Runbook
	severity := "\n <strong>Severity:</strong> " + alert.Severity

	// Best effort attempt to marshal Alert Context
	marshaledContext, _ := jsoniter.MarshalToString(alert.Context)
	alertContext := "\n <strong>AlertContext:</strong> " + marshaledContext

	opsgenieRequest := map[string]interface{}{
		"message":     generateAlertTitle(alert),
		"description": description + link + runBook + severity + alertContext,
		"tags":        alert.Tags,
		"priority":    pantherToOpsGeniePriority[alert.Severity],
	}
	authorization := "GenieKey " + config.APIKey
	requestHeader := map[string]string{
		AuthorizationHTTPHeader: authorization,
	}

	requestEndpoint := GetOpsGenieRegionalEndpoint(config.ServiceRegion)

	postInput := &PostInput{
		url:     requestEndpoint,
		body:    opsgenieRequest,
		headers: requestHeader,
	}
	return client.httpWrapper.post(ctx, postInput)
}
