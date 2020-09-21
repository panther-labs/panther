// Code generated by go-swagger; DO NOT EDIT.

package models

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

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

// IntegrationType Resource lives in this type of account
//
// swagger:model integrationType
type IntegrationType string

const (

	// IntegrationTypeAws captures enum value "aws"
	IntegrationTypeAws IntegrationType = "aws"
)

// for schema
var integrationTypeEnum []interface{}

func init() {
	var res []IntegrationType
	if err := json.Unmarshal([]byte(`["aws"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		integrationTypeEnum = append(integrationTypeEnum, v)
	}
}

func (m IntegrationType) validateIntegrationTypeEnum(path, location string, value IntegrationType) error {
	if err := validate.EnumCase(path, location, value, integrationTypeEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this integration type
func (m IntegrationType) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateIntegrationTypeEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
