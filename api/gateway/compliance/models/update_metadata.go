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

// UpdateMetadata update metadata
//
// swagger:model UpdateMetadata
type UpdateMetadata struct {

	// policy Id
	// Required: true
	PolicyID PolicyID `json:"policyId"`

	// severity
	// Required: true
	Severity PolicySeverity `json:"severity"`

	// suppressions
	Suppressions IgnoreSet `json:"suppressions,omitempty"`
}

// Validate validates this update metadata
func (m *UpdateMetadata) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validatePolicyID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSeverity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSuppressions(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UpdateMetadata) validatePolicyID(formats strfmt.Registry) error {

	if err := m.PolicyID.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("policyId")
		}
		return err
	}

	return nil
}

func (m *UpdateMetadata) validateSeverity(formats strfmt.Registry) error {

	if err := m.Severity.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("severity")
		}
		return err
	}

	return nil
}

func (m *UpdateMetadata) validateSuppressions(formats strfmt.Registry) error {

	if swag.IsZero(m.Suppressions) { // not required
		return nil
	}

	if err := m.Suppressions.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("suppressions")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *UpdateMetadata) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UpdateMetadata) UnmarshalBinary(b []byte) error {
	var res UpdateMetadata
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
