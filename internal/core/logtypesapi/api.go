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

// Generate a lambda client using genlambdamux
//go:generate go run github.com/panther-labs/panther/pkg/x/apigen -pkg logtypesclient -out ./client/lambdaclient_gen.go

// API handles the business logic of LogTypesAPI
type API struct {
	ExternalAPI    ExternalAPI
	NativeLogTypes func() []string
}

// ExternalAPI handles the external actions required for API to be implemented
type ExternalAPI interface {
	ListLogTypes(ctx context.Context) ([]string, error)
}

// Models
// We should list all API models here until we update the generator to produce docs for the models used.
type AvailableLogTypes struct {
	LogTypes []string `json:"logTypes"`
}
