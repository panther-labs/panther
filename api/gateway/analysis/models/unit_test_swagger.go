// Code generated by go-swagger; DO NOT EDIT.

// Panther is a Cloud-Native SIEM for the Modern Security Team.
// Copyright (C) 2020 Panther Labs Inc
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// UnitTest unit test
//
// swagger:model UnitTest
type UnitTest struct {

	// expected result
	// Required: true
	ExpectedResult TestExpectedResult `json:"expectedResult"`

	// name
	// Required: true
	Name TestName `json:"name"`

	// resource
	// Required: true
	Resource TestResource `json:"resource"`

	// resource type
	// Required: true
	ResourceType TestResourceType `json:"resourceType"`
}

// Validate validates this unit test
func (m *UnitTest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateExpectedResult(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResource(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResourceType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UnitTest) validateExpectedResult(formats strfmt.Registry) error {

	if err := m.ExpectedResult.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("expectedResult")
		}
		return err
	}

	return nil
}

func (m *UnitTest) validateName(formats strfmt.Registry) error {

	if err := m.Name.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("name")
		}
		return err
	}

	return nil
}

func (m *UnitTest) validateResource(formats strfmt.Registry) error {

	if err := m.Resource.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("resource")
		}
		return err
	}

	return nil
}

func (m *UnitTest) validateResourceType(formats strfmt.Registry) error {

	if err := m.ResourceType.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("resourceType")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *UnitTest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UnitTest) UnmarshalBinary(b []byte) error {
	var res UnitTest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
