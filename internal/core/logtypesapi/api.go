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

import (
	"context"
)

const LambdaName = "panther-logtypes-api"

// Generate a lambda client using apigen
// nolint:lll
//go:generate go run github.com/panther-labs/panther/pkg/x/apigen -target LogTypesAPI -type lambdaclient -out ./lambdaclient_gen.go
// Generate models using apigen
// nolint:lll
//go:generate go run github.com/panther-labs/panther/pkg/x/apigen -target LogTypesAPI -type models -out ../../../api/lambda/logtypes/models_gen.go

// LogTypesAPI handles the business logic of log types LogTypesAPI
type LogTypesAPI struct {
	NativeLogTypes func() []string
	Database       LogTypesDatabase
}

// LogTypesDatabase handles the external actions required for LogTypesAPI to be implemented
type LogTypesDatabase interface {
	// Return an index of available log types
	IndexLogTypes(ctx context.Context) ([]string, error)
}
