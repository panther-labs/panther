// Code generated by apigen; DO NOT EDIT.
// package logtypesapi documents github.com/panther-labs/panther/internal/core/logtypesapi.LogTypesAPI
package logtypesapi

import "time"

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

// LogTypesAPI available endpoints
type LogTypesAPI interface {
	ListAvailableLogTypes() (ListAvailableLogTypesResponse, error)

	ListDeletedCustomLogs() (ListDeletedCustomLogsResponse, error)

	GetCustomLog(input GetCustomLogInput) (GetCustomLogResponse, error)

	PutCustomLog(input PutCustomLogInput) (PutCustomLogResponse, error)

	DelCustomLog(input DelCustomLogInput) (DelCustomLogResponse, error)

	ListCustomLogs() (ListCustomLogsResponse, error)

	GetSchema(input GetSchemaInput) (GetSchemaResponse, error)
}

// Models for LogTypesAPI

// LogTypesAPIPayload is the payload for calls to LogTypesAPI endpoints.
type LogTypesAPIPayload struct {
	ListAvailableLogTypes *struct{}
	ListDeletedCustomLogs *struct{}
	GetCustomLog          *GetCustomLogInput
	PutCustomLog          *PutCustomLogInput
	DelCustomLog          *DelCustomLogInput
	ListCustomLogs        *struct{}
	GetSchema             *GetSchemaInput
}

type DelCustomLogInput struct {
	LogType  string `json:"logType" validate:"required,startswith=Custom." description:"The log type id"`
	Revision int64  `json:"revision" validate:"min=1" description:"Log record revision"`
}

type DelCustomLogResponse struct {
	Error struct {
		Code    string `json:"code" validate:"required"`
		Message string `json:"message" validate:"required"`
	} `json:"error,omitempty" description:"The delete record"`
}

type GetCustomLogInput struct {
	LogType  string `json:"logType" validate:"required,startswith=Custom." description:"The log type id"`
	Revision int64  `json:"revision,omitempty" validate:"omitempty,min=1" description:"Log record revision (0 means latest)"`
}

type GetCustomLogResponse struct {
	Result struct {
		Name         string    `json:"logType" dynamodbav:"logType" validate:"required" description:"The schema id"`
		Revision     int64     `json:"revision" validate:"required,min=1" description:"Schema record revision"`
		Release      string    `json:"release,omitempty" description:"Managed schema release version"`
		UpdatedAt    time.Time `json:"updatedAt" description:"Last update timestamp of the record"`
		CreatedAt    time.Time `json:"createdAt" description:"Creation timestamp of the record"`
		Managed      bool      `json:"managed,omitempty" description:"Schema is managed by Panther"`
		Disabled     bool      `json:"disabled,omitempty" dynamodbav:"IsDeleted"  description:"Log record is deleted"`
		Description  string    `json:"description" description:"Log type description"`
		ReferenceURL string    `json:"referenceURL" description:"A URL with reference docs for the schema"`
		Spec         string    `json:"logSpec" dynamodbav:"logSpec" validate:"required" description:"The schema spec in YAML or JSON format"`
	} `json:"record,omitempty" description:"The custom log record (field omitted if an error occurred)"`
	Error struct {
		Code    string `json:"code" validate:"required"`
		Message string `json:"message" validate:"required"`
	} `json:"error,omitempty" description:"An error that occurred while fetching the record"`
}

type GetSchemaInput struct {
	Name     string `json:"name" validate:"required" description:"The schema id"`
	Revision int64  `json:"revision,omitempty" validate:"omitempty,min=1" description:"Schema record revision (0 means latest)"`
}

type GetSchemaResponse struct {
	Record struct {
		Name         string    `json:"logType" dynamodbav:"logType" validate:"required" description:"The schema id"`
		Revision     int64     `json:"revision" validate:"required,min=1" description:"Schema record revision"`
		Release      string    `json:"release,omitempty" description:"Managed schema release version"`
		UpdatedAt    time.Time `json:"updatedAt" description:"Last update timestamp of the record"`
		CreatedAt    time.Time `json:"createdAt" description:"Creation timestamp of the record"`
		Managed      bool      `json:"managed,omitempty" description:"Schema is managed by Panther"`
		Disabled     bool      `json:"disabled,omitempty" dynamodbav:"IsDeleted"  description:"Log record is deleted"`
		Description  string    `json:"description" description:"Log type description"`
		ReferenceURL string    `json:"referenceURL" description:"A URL with reference docs for the schema"`
		Spec         string    `json:"logSpec" dynamodbav:"logSpec" validate:"required" description:"The schema spec in YAML or JSON format"`
	} `json:"record,omitempty" description:"The schema record (field omitted if an error occurred)"`
	Error struct {
		Code    string `json:"code" validate:"required"`
		Message string `json:"message" validate:"required"`
	} `json:"error,omitempty" description:"An error that occurred while fetching the record"`
}

type ListAvailableLogTypesResponse struct {
	LogTypes []string `json:"logTypes"`
}

type ListCustomLogsResponse struct {
	Records []struct {
		Name         string    `json:"logType" dynamodbav:"logType" validate:"required" description:"The schema id"`
		Revision     int64     `json:"revision" validate:"required,min=1" description:"Schema record revision"`
		Release      string    `json:"release,omitempty" description:"Managed schema release version"`
		UpdatedAt    time.Time `json:"updatedAt" description:"Last update timestamp of the record"`
		CreatedAt    time.Time `json:"createdAt" description:"Creation timestamp of the record"`
		Managed      bool      `json:"managed,omitempty" description:"Schema is managed by Panther"`
		Disabled     bool      `json:"disabled,omitempty" dynamodbav:"IsDeleted"  description:"Log record is deleted"`
		Description  string    `json:"description" description:"Log type description"`
		ReferenceURL string    `json:"referenceURL" description:"A URL with reference docs for the schema"`
		Spec         string    `json:"logSpec" dynamodbav:"logSpec" validate:"required" description:"The schema spec in YAML or JSON format"`
	} `json:"customLogs" description:"Custom log records stored"`
	Error struct {
		Code    string `json:"code" validate:"required"`
		Message string `json:"message" validate:"required"`
	} `json:"error,omitempty" description:"An error that occurred during the operation"`
}

type ListDeletedCustomLogsResponse struct {
	LogTypes []string `json:"logTypes,omitempty" description:"A list of ids of deleted log types (omitted if an error occurred)"`
	Error    struct {
		Code    string `json:"code" validate:"required"`
		Message string `json:"message" validate:"required"`
	} `json:"error,omitempty" description:"An error that occurred while fetching the list"`
}

type PutCustomLogInput struct {
	LogType      string `json:"logType" validate:"required,startswith=Custom." description:"The log type id"`
	Revision     int64  `json:"revision,omitempty" validate:"omitempty,min=1" description:"Custom log record revision to update (if omitted a new record will be created)"`
	Description  string `json:"description" description:"Log type description"`
	ReferenceURL string `json:"referenceURL" description:"A URL with reference docs for the schema"`
	Spec         string `json:"logSpec" dynamodbav:"logSpec" validate:"required" description:"The schema spec in YAML or JSON format"`
}

type PutCustomLogResponse struct {
	Result struct {
		Name         string    `json:"logType" dynamodbav:"logType" validate:"required" description:"The schema id"`
		Revision     int64     `json:"revision" validate:"required,min=1" description:"Schema record revision"`
		Release      string    `json:"release,omitempty" description:"Managed schema release version"`
		UpdatedAt    time.Time `json:"updatedAt" description:"Last update timestamp of the record"`
		CreatedAt    time.Time `json:"createdAt" description:"Creation timestamp of the record"`
		Managed      bool      `json:"managed,omitempty" description:"Schema is managed by Panther"`
		Disabled     bool      `json:"disabled,omitempty" dynamodbav:"IsDeleted"  description:"Log record is deleted"`
		Description  string    `json:"description" description:"Log type description"`
		ReferenceURL string    `json:"referenceURL" description:"A URL with reference docs for the schema"`
		Spec         string    `json:"logSpec" dynamodbav:"logSpec" validate:"required" description:"The schema spec in YAML or JSON format"`
	} `json:"record,omitempty" description:"The modified record (field is omitted if an error occurred)"`
	Error struct {
		Code    string `json:"code" validate:"required"`
		Message string `json:"message" validate:"required"`
	} `json:"error,omitempty" description:"An error that occurred during the operation"`
}
