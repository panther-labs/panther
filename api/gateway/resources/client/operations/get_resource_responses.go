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

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/panther-labs/panther/api/gateway/resources/models"
)

// GetResourceReader is a Reader for the GetResource structure.
type GetResourceReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetResourceReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetResourceOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetResourceBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetResourceNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetResourceInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetResourceOK creates a GetResourceOK with default headers values
func NewGetResourceOK() *GetResourceOK {
	return &GetResourceOK{}
}

/*GetResourceOK handles this case with default header values.

OK
*/
type GetResourceOK struct {
	Payload *models.Resource
}

func (o *GetResourceOK) Error() string {
	return fmt.Sprintf("[GET /resource][%d] getResourceOK  %+v", 200, o.Payload)
}

func (o *GetResourceOK) GetPayload() *models.Resource {
	return o.Payload
}

func (o *GetResourceOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Resource)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetResourceBadRequest creates a GetResourceBadRequest with default headers values
func NewGetResourceBadRequest() *GetResourceBadRequest {
	return &GetResourceBadRequest{}
}

/*GetResourceBadRequest handles this case with default header values.

Bad request
*/
type GetResourceBadRequest struct {
	Payload *models.Error
}

func (o *GetResourceBadRequest) Error() string {
	return fmt.Sprintf("[GET /resource][%d] getResourceBadRequest  %+v", 400, o.Payload)
}

func (o *GetResourceBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetResourceBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetResourceNotFound creates a GetResourceNotFound with default headers values
func NewGetResourceNotFound() *GetResourceNotFound {
	return &GetResourceNotFound{}
}

/*GetResourceNotFound handles this case with default header values.

Resource does not exist
*/
type GetResourceNotFound struct {
}

func (o *GetResourceNotFound) Error() string {
	return fmt.Sprintf("[GET /resource][%d] getResourceNotFound ", 404)
}

func (o *GetResourceNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetResourceInternalServerError creates a GetResourceInternalServerError with default headers values
func NewGetResourceInternalServerError() *GetResourceInternalServerError {
	return &GetResourceInternalServerError{}
}

/*GetResourceInternalServerError handles this case with default header values.

Internal server error
*/
type GetResourceInternalServerError struct {
}

func (o *GetResourceInternalServerError) Error() string {
	return fmt.Sprintf("[GET /resource][%d] getResourceInternalServerError ", 500)
}

func (o *GetResourceInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
