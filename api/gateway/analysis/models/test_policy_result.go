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

// TestPolicyResult test policy result
//
// swagger:model TestPolicyResult
type TestPolicyResult struct {

	// test summary
	// Required: true
	TestSummary TestSummary `json:"testSummary"`

	// tests errored
	// Required: true
	TestsErrored TestsErrored `json:"testsErrored"`

	// tests failed
	// Required: true
	TestsFailed TestsFailed `json:"testsFailed"`

	// tests passed
	// Required: true
	TestsPassed TestsPassed `json:"testsPassed"`
}

// Validate validates this test policy result
func (m *TestPolicyResult) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateTestSummary(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTestsErrored(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTestsFailed(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTestsPassed(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TestPolicyResult) validateTestSummary(formats strfmt.Registry) error {

	if err := m.TestSummary.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("testSummary")
		}
		return err
	}

	return nil
}

func (m *TestPolicyResult) validateTestsErrored(formats strfmt.Registry) error {

	if err := validate.Required("testsErrored", "body", m.TestsErrored); err != nil {
		return err
	}

	if err := m.TestsErrored.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("testsErrored")
		}
		return err
	}

	return nil
}

func (m *TestPolicyResult) validateTestsFailed(formats strfmt.Registry) error {

	if err := validate.Required("testsFailed", "body", m.TestsFailed); err != nil {
		return err
	}

	if err := m.TestsFailed.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("testsFailed")
		}
		return err
	}

	return nil
}

func (m *TestPolicyResult) validateTestsPassed(formats strfmt.Registry) error {

	if err := validate.Required("testsPassed", "body", m.TestsPassed); err != nil {
		return err
	}

	if err := m.TestsPassed.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("testsPassed")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *TestPolicyResult) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TestPolicyResult) UnmarshalBinary(b []byte) error {
	var res TestPolicyResult
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
