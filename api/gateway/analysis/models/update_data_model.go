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

// UpdateDataModel update data model
//
// swagger:model UpdateDataModel
type UpdateDataModel struct {

	// body
	Body Body `json:"body,omitempty"`

	// description
	Description Description `json:"description,omitempty"`

	// enabled
	// Required: true
	Enabled Enabled `json:"enabled"`

	// id
	// Required: true
	ID ID `json:"id"`

	// log types
	LogTypes TypeSet `json:"logTypes,omitempty"`

	// mappings
	// Required: true
	Mappings DataModelMappings `json:"mappings"`

	// user Id
	// Required: true
	UserID UserID `json:"userId"`
}

// Validate validates this update data model
func (m *UpdateDataModel) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateBody(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDescription(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEnabled(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLogTypes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMappings(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUserID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UpdateDataModel) validateBody(formats strfmt.Registry) error {

	if swag.IsZero(m.Body) { // not required
		return nil
	}

	if err := m.Body.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("body")
		}
		return err
	}

	return nil
}

func (m *UpdateDataModel) validateDescription(formats strfmt.Registry) error {

	if swag.IsZero(m.Description) { // not required
		return nil
	}

	if err := m.Description.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("description")
		}
		return err
	}

	return nil
}

func (m *UpdateDataModel) validateEnabled(formats strfmt.Registry) error {

	if err := m.Enabled.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("enabled")
		}
		return err
	}

	return nil
}

func (m *UpdateDataModel) validateID(formats strfmt.Registry) error {

	if err := m.ID.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("id")
		}
		return err
	}

	return nil
}

func (m *UpdateDataModel) validateLogTypes(formats strfmt.Registry) error {

	if swag.IsZero(m.LogTypes) { // not required
		return nil
	}

	if err := m.LogTypes.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("logTypes")
		}
		return err
	}

	return nil
}

func (m *UpdateDataModel) validateMappings(formats strfmt.Registry) error {

	if err := validate.Required("mappings", "body", m.Mappings); err != nil {
		return err
	}

	if err := m.Mappings.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("mappings")
		}
		return err
	}

	return nil
}

func (m *UpdateDataModel) validateUserID(formats strfmt.Registry) error {

	if err := m.UserID.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("userId")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *UpdateDataModel) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UpdateDataModel) UnmarshalBinary(b []byte) error {
	var res UpdateDataModel
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
