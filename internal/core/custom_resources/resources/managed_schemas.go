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
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/core/logtypesapi"
	"github.com/panther-labs/panther/internal/log_analysis/managedschemas"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

type UpdateManagedSchemas struct {
}

func customUpdateManagedSchemas(ctx context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	logger := lambdalogger.FromContext(ctx).With(
		zap.String("requestID", event.RequestID),
		zap.String("requestType", string(event.RequestType)),
		zap.String("stackID", event.StackID),
		zap.String("eventPhysicalResourceID", event.PhysicalResourceID),
	)
	logger.Info("received UpdateManagedSchemas event", zap.String("requestType", string(event.RequestType)))
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		// It's important to always return this physicalResourceID
		const physicalResourceID = "custom:schemas:update-managed-schemas"
		input := logtypesapi.UpdateManagedSchemasInput{
			Release: managedschemas.ReleaseVersion,
		}
		if _, err := logtypesAPI.UpdateManagedSchemas(ctx, &input); err != nil {
			return physicalResourceID, nil, errors.Wrapf(err, "failed to update managed schemas %s", managedschemas.ReleaseVersion)
		}
		return physicalResourceID, nil, nil
	case cfn.RequestDelete:
		// Deleting all log processing databases
		return event.PhysicalResourceID, nil, nil
	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}
