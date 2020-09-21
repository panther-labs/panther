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

// ModifyRuleReader is a Reader for the ModifyRule structure.
type ModifyRuleReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ModifyRuleReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewModifyRuleOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewModifyRuleBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewModifyRuleNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewModifyRuleInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewModifyRuleOK creates a ModifyRuleOK with default headers values
func NewModifyRuleOK() *ModifyRuleOK {
	return &ModifyRuleOK{}
}

/*ModifyRuleOK handles this case with default header values.

OK
*/
type ModifyRuleOK struct {
	Payload *models.Rule
}

func (o *ModifyRuleOK) Error() string {
	return fmt.Sprintf("[POST /rule/update][%d] modifyRuleOK  %+v", 200, o.Payload)
}

func (o *ModifyRuleOK) GetPayload() *models.Rule {
	return o.Payload
}

func (o *ModifyRuleOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Rule)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewModifyRuleBadRequest creates a ModifyRuleBadRequest with default headers values
func NewModifyRuleBadRequest() *ModifyRuleBadRequest {
	return &ModifyRuleBadRequest{}
}

/*ModifyRuleBadRequest handles this case with default header values.

Bad request
*/
type ModifyRuleBadRequest struct {
	Payload *models.Error
}

func (o *ModifyRuleBadRequest) Error() string {
	return fmt.Sprintf("[POST /rule/update][%d] modifyRuleBadRequest  %+v", 400, o.Payload)
}

func (o *ModifyRuleBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *ModifyRuleBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewModifyRuleNotFound creates a ModifyRuleNotFound with default headers values
func NewModifyRuleNotFound() *ModifyRuleNotFound {
	return &ModifyRuleNotFound{}
}

/*ModifyRuleNotFound handles this case with default header values.

Rule not found
*/
type ModifyRuleNotFound struct {
}

func (o *ModifyRuleNotFound) Error() string {
	return fmt.Sprintf("[POST /rule/update][%d] modifyRuleNotFound ", 404)
}

func (o *ModifyRuleNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewModifyRuleInternalServerError creates a ModifyRuleInternalServerError with default headers values
func NewModifyRuleInternalServerError() *ModifyRuleInternalServerError {
	return &ModifyRuleInternalServerError{}
}

/*ModifyRuleInternalServerError handles this case with default header values.

Internal server error
*/
type ModifyRuleInternalServerError struct {
}

func (o *ModifyRuleInternalServerError) Error() string {
	return fmt.Sprintf("[POST /rule/update][%d] modifyRuleInternalServerError ", 500)
}

func (o *ModifyRuleInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
