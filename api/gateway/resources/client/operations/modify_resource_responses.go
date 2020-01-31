// Code generated by go-swagger; DO NOT EDIT.

package operations

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/panther-labs/panther/api/gateway/resources/models"
)

// ModifyResourceReader is a Reader for the ModifyResource structure.
type ModifyResourceReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ModifyResourceReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewModifyResourceOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewModifyResourceBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewModifyResourceNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewModifyResourceInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewModifyResourceOK creates a ModifyResourceOK with default headers values
func NewModifyResourceOK() *ModifyResourceOK {
	return &ModifyResourceOK{}
}

/*ModifyResourceOK handles this case with default header values.

OK
*/
type ModifyResourceOK struct {
}

func (o *ModifyResourceOK) Error() string {
	return fmt.Sprintf("[PATCH /resource][%d] modifyResourceOK ", 200)
}

func (o *ModifyResourceOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewModifyResourceBadRequest creates a ModifyResourceBadRequest with default headers values
func NewModifyResourceBadRequest() *ModifyResourceBadRequest {
	return &ModifyResourceBadRequest{}
}

/*ModifyResourceBadRequest handles this case with default header values.

Malformed request
*/
type ModifyResourceBadRequest struct {
	Payload *models.Error
}

func (o *ModifyResourceBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /resource][%d] modifyResourceBadRequest  %+v", 400, o.Payload)
}

func (o *ModifyResourceBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *ModifyResourceBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewModifyResourceNotFound creates a ModifyResourceNotFound with default headers values
func NewModifyResourceNotFound() *ModifyResourceNotFound {
	return &ModifyResourceNotFound{}
}

/*ModifyResourceNotFound handles this case with default header values.

Resource does not exist
*/
type ModifyResourceNotFound struct {
	Payload *models.Error
}

func (o *ModifyResourceNotFound) Error() string {
	return fmt.Sprintf("[PATCH /resource][%d] modifyResourceNotFound  %+v", 404, o.Payload)
}

func (o *ModifyResourceNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ModifyResourceNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewModifyResourceInternalServerError creates a ModifyResourceInternalServerError with default headers values
func NewModifyResourceInternalServerError() *ModifyResourceInternalServerError {
	return &ModifyResourceInternalServerError{}
}

/*ModifyResourceInternalServerError handles this case with default header values.

Internal server error
*/
type ModifyResourceInternalServerError struct {
}

func (o *ModifyResourceInternalServerError) Error() string {
	return fmt.Sprintf("[PATCH /resource][%d] modifyResourceInternalServerError ", 500)
}

func (o *ModifyResourceInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
