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

// ActiveSuppressCount active suppress count
//
// swagger:model ActiveSuppressCount
type ActiveSuppressCount struct {

	// active
	// Required: true
	Active *StatusCount `json:"active"`

	// suppressed
	// Required: true
	Suppressed *StatusCount `json:"suppressed"`
}

// Validate validates this active suppress count
func (m *ActiveSuppressCount) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateActive(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSuppressed(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ActiveSuppressCount) validateActive(formats strfmt.Registry) error {

	if err := validate.Required("active", "body", m.Active); err != nil {
		return err
	}

	if m.Active != nil {
		if err := m.Active.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("active")
			}
			return err
		}
	}

	return nil
}

func (m *ActiveSuppressCount) validateSuppressed(formats strfmt.Registry) error {

	if err := validate.Required("suppressed", "body", m.Suppressed); err != nil {
		return err
	}

	if m.Suppressed != nil {
		if err := m.Suppressed.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("suppressed")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ActiveSuppressCount) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ActiveSuppressCount) UnmarshalBinary(b []byte) error {
	var res ActiveSuppressCount
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
