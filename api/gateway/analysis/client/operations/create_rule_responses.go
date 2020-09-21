// Code generated by go-swagger; DO NOT EDIT.

package operations

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
	"fmt"
	"io"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/panther-labs/panther/api/gateway/analysis/models"
)

// CreateRuleReader is a Reader for the CreateRule structure.
type CreateRuleReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateRuleReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateRuleCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateRuleBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewCreateRuleConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewCreateRuleInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCreateRuleCreated creates a CreateRuleCreated with default headers values
func NewCreateRuleCreated() *CreateRuleCreated {
	return &CreateRuleCreated{}
}

/*CreateRuleCreated handles this case with default header values.

Rule created successfully
*/
type CreateRuleCreated struct {
	Payload *models.Rule
}

func (o *CreateRuleCreated) Error() string {
	return fmt.Sprintf("[POST /rule][%d] createRuleCreated  %+v", 201, o.Payload)
}

func (o *CreateRuleCreated) GetPayload() *models.Rule {
	return o.Payload
}

func (o *CreateRuleCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Rule)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateRuleBadRequest creates a CreateRuleBadRequest with default headers values
func NewCreateRuleBadRequest() *CreateRuleBadRequest {
	return &CreateRuleBadRequest{}
}

/*CreateRuleBadRequest handles this case with default header values.

Bad request
*/
type CreateRuleBadRequest struct {
	Payload *models.Error
}

func (o *CreateRuleBadRequest) Error() string {
	return fmt.Sprintf("[POST /rule][%d] createRuleBadRequest  %+v", 400, o.Payload)
}

func (o *CreateRuleBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *CreateRuleBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateRuleConflict creates a CreateRuleConflict with default headers values
func NewCreateRuleConflict() *CreateRuleConflict {
	return &CreateRuleConflict{}
}

/*CreateRuleConflict handles this case with default header values.

Rule or policy with the given ID already exists
*/
type CreateRuleConflict struct {
}

func (o *CreateRuleConflict) Error() string {
	return fmt.Sprintf("[POST /rule][%d] createRuleConflict ", 409)
}

func (o *CreateRuleConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewCreateRuleInternalServerError creates a CreateRuleInternalServerError with default headers values
func NewCreateRuleInternalServerError() *CreateRuleInternalServerError {
	return &CreateRuleInternalServerError{}
}

/*CreateRuleInternalServerError handles this case with default header values.

Internal server error
*/
type CreateRuleInternalServerError struct {
}

func (o *CreateRuleInternalServerError) Error() string {
	return fmt.Sprintf("[POST /rule][%d] createRuleInternalServerError ", 500)
}

func (o *CreateRuleInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
