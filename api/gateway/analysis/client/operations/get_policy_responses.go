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

// GetPolicyReader is a Reader for the GetPolicy structure.
type GetPolicyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetPolicyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetPolicyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetPolicyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetPolicyNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetPolicyInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetPolicyOK creates a GetPolicyOK with default headers values
func NewGetPolicyOK() *GetPolicyOK {
	return &GetPolicyOK{}
}

/*GetPolicyOK handles this case with default header values.

OK
*/
type GetPolicyOK struct {
	Payload *models.Policy
}

func (o *GetPolicyOK) Error() string {
	return fmt.Sprintf("[GET /policy][%d] getPolicyOK  %+v", 200, o.Payload)
}

func (o *GetPolicyOK) GetPayload() *models.Policy {
	return o.Payload
}

func (o *GetPolicyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Policy)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPolicyBadRequest creates a GetPolicyBadRequest with default headers values
func NewGetPolicyBadRequest() *GetPolicyBadRequest {
	return &GetPolicyBadRequest{}
}

/*GetPolicyBadRequest handles this case with default header values.

Bad request
*/
type GetPolicyBadRequest struct {
	Payload *models.Error
}

func (o *GetPolicyBadRequest) Error() string {
	return fmt.Sprintf("[GET /policy][%d] getPolicyBadRequest  %+v", 400, o.Payload)
}

func (o *GetPolicyBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetPolicyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPolicyNotFound creates a GetPolicyNotFound with default headers values
func NewGetPolicyNotFound() *GetPolicyNotFound {
	return &GetPolicyNotFound{}
}

/*GetPolicyNotFound handles this case with default header values.

Policy does not exist
*/
type GetPolicyNotFound struct {
}

func (o *GetPolicyNotFound) Error() string {
	return fmt.Sprintf("[GET /policy][%d] getPolicyNotFound ", 404)
}

func (o *GetPolicyNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetPolicyInternalServerError creates a GetPolicyInternalServerError with default headers values
func NewGetPolicyInternalServerError() *GetPolicyInternalServerError {
	return &GetPolicyInternalServerError{}
}

/*GetPolicyInternalServerError handles this case with default header values.

Internal server error
*/
type GetPolicyInternalServerError struct {
}

func (o *GetPolicyInternalServerError) Error() string {
	return fmt.Sprintf("[GET /policy][%d] getPolicyInternalServerError ", 500)
}

func (o *GetPolicyInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
