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
	"fmt"

	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
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
	LambdaClient   lambdaiface.LambdaAPI
}

// LogTypesDatabase handles the external actions required for LogTypesAPI to be implemented
type LogTypesDatabase interface {
	// Return an index of available log types
	IndexLogTypes(ctx context.Context) ([]string, error)

	// Create a new custom log record
	CreateCustomLog(ctx context.Context, id string, params *CustomLog) (*CustomLogRecord, error)
	// Get a single custom log record
	GetCustomLog(ctx context.Context, id string, revision int64) (*CustomLogRecord, error)
	// Update a custom log record
	UpdateCustomLog(ctx context.Context, id string, currentRevision int64, params *CustomLog) (*CustomLogRecord, error)
	// Delete a custom log record
	DeleteCustomLog(ctx context.Context, id string, currentRevision int64) error
	// Get multiple custom log records at their latest revision
	BatchGetCustomLogs(ctx context.Context, ids ...string) ([]*CustomLogRecord, error)
}

const (
	// ErrRevisionConflict is the error code to use when there is a revision conflict
	ErrRevisionConflict = "RevisionConflict"
	ErrAlreadyExists    = "AlreadyExists"
	ErrNotFound         = "NotFound"
	ErrInUse            = "InUse"
)

// APIError is an error that has a code and a message and is returned as part of the API response
type APIError struct {
	Code    string `json:"code" validate:"required"`
	Message string `json:"message" validate:"required"`
}

// Error implements error interface
func (e *APIError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// NewAPIError creates a new API error
func NewAPIError(code, message string) *APIError {
	return &APIError{
		Code:    code,
		Message: message,
	}
}

// WrapAPIError wraps an error to be an API error keeping code and message if available
func WrapAPIError(err error) *APIError {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr
	}
	type errWithCode interface {
		error
		Code() string
		Message() string
	}
	if e, ok := err.(errWithCode); ok {
		return &APIError{
			Code:    e.Code(),
			Message: e.Message(),
		}
	}
	return &APIError{
		Code:    "UnknownError",
		Message: err.Error(),
	}
}
