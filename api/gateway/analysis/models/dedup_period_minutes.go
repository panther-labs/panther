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
	"github.com/go-openapi/validate"
)

// DedupPeriodMinutes The time in minutes for which we deduplicate events when generating alerts for log analysis
//
// swagger:model dedupPeriodMinutes
type DedupPeriodMinutes int64

// Validate validates this dedup period minutes
func (m DedupPeriodMinutes) Validate(formats strfmt.Registry) error {
	var res []error

	if err := validate.MinimumInt("", "body", int64(m), 15, false); err != nil {
		return err
	}

	if err := validate.MaximumInt("", "body", int64(m), 1440, false); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
