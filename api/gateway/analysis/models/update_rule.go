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
)

// UpdateRule update rule
//
// swagger:model UpdateRule
type UpdateRule struct {

	// body
	// Required: true
	Body Body `json:"body"`

	// dedup period minutes
	DedupPeriodMinutes DedupPeriodMinutes `json:"dedupPeriodMinutes,omitempty"`

	// description
	Description Description `json:"description,omitempty"`

	// display name
	DisplayName DisplayName `json:"displayName,omitempty"`

	// enabled
	// Required: true
	Enabled Enabled `json:"enabled"`

	// id
	// Required: true
	ID ID `json:"id"`

	// log types
	LogTypes TypeSet `json:"logTypes,omitempty"`

	// output ids
	OutputIds OutputIds `json:"outputIds,omitempty"`

	// reference
	Reference Reference `json:"reference,omitempty"`

	// reports
	Reports Reports `json:"reports,omitempty"`

	// runbook
	Runbook Runbook `json:"runbook,omitempty"`

	// severity
	// Required: true
	Severity Severity `json:"severity"`

	// tags
	Tags Tags `json:"tags,omitempty"`

	// tests
	Tests TestSuite `json:"tests,omitempty"`

	// user Id
	// Required: true
	UserID UserID `json:"userId"`
}

// Validate validates this update rule
func (m *UpdateRule) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateBody(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDedupPeriodMinutes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDescription(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDisplayName(formats); err != nil {
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

	if err := m.validateOutputIds(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateReference(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateReports(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRunbook(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSeverity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTags(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTests(formats); err != nil {
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

func (m *UpdateRule) validateBody(formats strfmt.Registry) error {

	if err := m.Body.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("body")
		}
		return err
	}

	return nil
}

func (m *UpdateRule) validateDedupPeriodMinutes(formats strfmt.Registry) error {

	if swag.IsZero(m.DedupPeriodMinutes) { // not required
		return nil
	}

	if err := m.DedupPeriodMinutes.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("dedupPeriodMinutes")
		}
		return err
	}

	return nil
}

func (m *UpdateRule) validateDescription(formats strfmt.Registry) error {

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

func (m *UpdateRule) validateDisplayName(formats strfmt.Registry) error {

	if swag.IsZero(m.DisplayName) { // not required
		return nil
	}

	if err := m.DisplayName.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("displayName")
		}
		return err
	}

	return nil
}

func (m *UpdateRule) validateEnabled(formats strfmt.Registry) error {

	if err := m.Enabled.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("enabled")
		}
		return err
	}

	return nil
}

func (m *UpdateRule) validateID(formats strfmt.Registry) error {

	if err := m.ID.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("id")
		}
		return err
	}

	return nil
}

func (m *UpdateRule) validateLogTypes(formats strfmt.Registry) error {

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

func (m *UpdateRule) validateOutputIds(formats strfmt.Registry) error {

	if swag.IsZero(m.OutputIds) { // not required
		return nil
	}

	if err := m.OutputIds.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("outputIds")
		}
		return err
	}

	return nil
}

func (m *UpdateRule) validateReference(formats strfmt.Registry) error {

	if swag.IsZero(m.Reference) { // not required
		return nil
	}

	if err := m.Reference.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("reference")
		}
		return err
	}

	return nil
}

func (m *UpdateRule) validateReports(formats strfmt.Registry) error {

	if swag.IsZero(m.Reports) { // not required
		return nil
	}

	if err := m.Reports.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("reports")
		}
		return err
	}

	return nil
}

func (m *UpdateRule) validateRunbook(formats strfmt.Registry) error {

	if swag.IsZero(m.Runbook) { // not required
		return nil
	}

	if err := m.Runbook.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("runbook")
		}
		return err
	}

	return nil
}

func (m *UpdateRule) validateSeverity(formats strfmt.Registry) error {

	if err := m.Severity.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("severity")
		}
		return err
	}

	return nil
}

func (m *UpdateRule) validateTags(formats strfmt.Registry) error {

	if swag.IsZero(m.Tags) { // not required
		return nil
	}

	if err := m.Tags.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("tags")
		}
		return err
	}

	return nil
}

func (m *UpdateRule) validateTests(formats strfmt.Registry) error {

	if swag.IsZero(m.Tests) { // not required
		return nil
	}

	if err := m.Tests.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("tests")
		}
		return err
	}

	return nil
}

func (m *UpdateRule) validateUserID(formats strfmt.Registry) error {

	if err := m.UserID.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("userId")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *UpdateRule) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UpdateRule) UnmarshalBinary(b []byte) error {
	var res UpdateRule
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
