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

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
	"github.com/panther-labs/panther/internal/log_analysis/managedschemas"
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
	Database          SchemaDatabase
	UpdateDataCatalog func(ctx context.Context, logType string, from, to []logschema.FieldSchema) error
	LogTypesInUse     func(ctx context.Context) ([]string, error)
	ManagedSchemas    managedschemas.ReleaseFeeder
}

// SchemaDatabase handles the external actions required for LogTypesAPI to be implemented
type SchemaDatabase interface {
	// GetSchema gets a single schema record
	GetSchema(ctx context.Context, id string) (*SchemaRecord, error)
	// PutSchema puts a single schema record
	PutSchema(ctx context.Context, id string, record *SchemaRecord) (*SchemaRecord, error)
	// ScanSchemas iterates through all schema records as long as scan returns true
	ScanSchemas(ctx context.Context, scan ScanSchemaFunc) error
}

type ScanSchemaFunc func(r *SchemaRecord) bool

const (
	// ErrRevisionConflict is the error code to use when there is a revision conflict
	ErrRevisionConflict = "RevisionConflict"
	ErrAlreadyExists    = "AlreadyExists"
	ErrNotFound         = "NotFound"
	ErrInUse            = "InUse"
	ErrInvalidUpdate    = "InvalidUpdate"
	ErrInvalidSyntax    = "InvalidSyntax"
	ErrInvalidLogSchema = "InvalidLogSchema"
	ErrServerError      = "ServerError"
)

// APIError is an error that has a code and a message and is returned as part of the API response
type APIError struct {
	Code    string `json:"code" validate:"required"`
	Message string `json:"message" validate:"required"`
	reason  error
}

func (e *APIError) Unwrap() error {
	return e.reason
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

type ErrorReply struct {
	Error *APIError `json:"error"`
}

func WrapAPIError(err error) *APIError {
	if err == nil {
		return nil
	}
	if apiErr := AsAPIError(err); apiErr != nil {
		return apiErr
	}
	// AWS errors implement this interface
	// We use their code to help with identifying the error but we keep the input error message.
	var errWithCode interface {
		Code() string
	}
	if errors.As(err, &errWithCode) {
		return &APIError{
			Code:    errWithCode.Code(),
			Message: err.Error(),
			reason:  err,
		}
	}
	// Return all unknown errors as 'ServerError'
	return &APIError{
		Code:    ErrServerError,
		Message: err.Error(),
		reason:  err,
	}
}

func AsAPIError(err error) *APIError {
	apiErr := &APIError{}
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return nil
}
