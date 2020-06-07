package resources

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

	"github.com/aws/aws-lambda-go/cfn"

	"github.com/panther-labs/panther/api/lambda/organization/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

type PantherSettingsProperties = models.GeneralSettings

func customPantherSettings(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		var props PantherSettingsProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return "", nil, err
		}

		input := models.LambdaInput{UpdateSettings: &props}
		return "custom:panther-settings:singleton", nil, genericapi.Invoke(
			lambdaClient, "panther-organization-api", &input, nil)

	default:
		// skip deletes - settings can't be "deleted", only changed
		return event.PhysicalResourceID, nil, nil
	}
}
