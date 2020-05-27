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
	"fmt"

	"github.com/aws/aws-lambda-go/cfn"

	"github.com/panther-labs/panther/pkg/awsathena"
)

type AthenaInitProperties struct {
	AthenaResultsBucket string `validate:"required"`
}

func customAthenaInit(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	const resourceID = "custom:athena:init"
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		var props AthenaInitProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return resourceID, nil, err
		}

		// Workgroup "primary" is default.
		const workgroup = "primary"
		if err := awsathena.WorkgroupAssociateS3(getSession(), workgroup, props.AthenaResultsBucket); err != nil {
			return resourceID, nil, fmt.Errorf("failed to associate %s Athena workgroup with %s bucket: %v",
				workgroup, props.AthenaResultsBucket, err)
		}

		return resourceID, nil, nil
	case cfn.RequestDelete: // noop
		return event.PhysicalResourceID, nil, nil

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}
