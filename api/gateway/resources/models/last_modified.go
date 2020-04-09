// Code generated by go-swagger; DO NOT EDIT.

// A Cloud-Native SIEM for the Modern Security Team
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
	"github.com/go-openapi/validate"
)

// LastModified When the resource state was last updated in the Panther database
//
// swagger:model lastModified
type LastModified strfmt.DateTime

// UnmarshalJSON sets a LastModified value from JSON input
func (m *LastModified) UnmarshalJSON(b []byte) error {
	return ((*strfmt.DateTime)(m)).UnmarshalJSON(b)
}

// MarshalJSON retrieves a LastModified value as JSON output
func (m LastModified) MarshalJSON() ([]byte, error) {
	return (strfmt.DateTime(m)).MarshalJSON()
}

// Validate validates this last modified
func (m LastModified) Validate(formats strfmt.Registry) error {
	var res []error

	if err := validate.FormatOf("", "body", "date-time", strfmt.DateTime(m).String(), formats); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// MarshalBinary interface implementation
func (m *LastModified) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *LastModified) UnmarshalBinary(b []byte) error {
	var res LastModified
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
