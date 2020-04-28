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
	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// TestPolicy test policy
//
// swagger:model TestPolicy
type TestPolicy struct {

	// analysis type
	// Required: true
	AnalysisType AnalysisType `json:"analysisType"`

	// body
	// Required: true
	Body Body `json:"body"`

	// resource types
	// Required: true
	ResourceTypes TypeSet `json:"resourceTypes"`

	// tests
	// Required: true
	Tests TestSuite `json:"tests"`
}

// Validate validates this test policy
func (m *TestPolicy) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAnalysisType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateBody(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResourceTypes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTests(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TestPolicy) validateAnalysisType(formats strfmt.Registry) error {

	if err := m.AnalysisType.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("analysisType")
		}
		return err
	}

	return nil
}

func (m *TestPolicy) validateBody(formats strfmt.Registry) error {

	if err := m.Body.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("body")
		}
		return err
	}

	return nil
}

func (m *TestPolicy) validateResourceTypes(formats strfmt.Registry) error {

	if err := validate.Required("resourceTypes", "body", m.ResourceTypes); err != nil {
		return err
	}

	if err := m.ResourceTypes.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("resourceTypes")
		}
		return err
	}

	return nil
}

func (m *TestPolicy) validateTests(formats strfmt.Registry) error {

	if err := validate.Required("tests", "body", m.Tests); err != nil {
		return err
	}

	if err := m.Tests.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("tests")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *TestPolicy) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TestPolicy) UnmarshalBinary(b []byte) error {
	var res TestPolicy
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
