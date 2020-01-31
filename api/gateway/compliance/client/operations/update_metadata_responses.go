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

	models "github.com/panther-labs/panther/api/gateway/compliance/models"
)

// UpdateMetadataReader is a Reader for the UpdateMetadata structure.
type UpdateMetadataReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateMetadataReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateMetadataOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateMetadataBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewUpdateMetadataInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewUpdateMetadataOK creates a UpdateMetadataOK with default headers values
func NewUpdateMetadataOK() *UpdateMetadataOK {
	return &UpdateMetadataOK{}
}

/*UpdateMetadataOK handles this case with default header values.

OK
*/
type UpdateMetadataOK struct {
}

func (o *UpdateMetadataOK) Error() string {
	return fmt.Sprintf("[POST /update][%d] updateMetadataOK ", 200)
}

func (o *UpdateMetadataOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewUpdateMetadataBadRequest creates a UpdateMetadataBadRequest with default headers values
func NewUpdateMetadataBadRequest() *UpdateMetadataBadRequest {
	return &UpdateMetadataBadRequest{}
}

/*UpdateMetadataBadRequest handles this case with default header values.

Bad request
*/
type UpdateMetadataBadRequest struct {
	Payload *models.Error
}

func (o *UpdateMetadataBadRequest) Error() string {
	return fmt.Sprintf("[POST /update][%d] updateMetadataBadRequest  %+v", 400, o.Payload)
}

func (o *UpdateMetadataBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *UpdateMetadataBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateMetadataInternalServerError creates a UpdateMetadataInternalServerError with default headers values
func NewUpdateMetadataInternalServerError() *UpdateMetadataInternalServerError {
	return &UpdateMetadataInternalServerError{}
}

/*UpdateMetadataInternalServerError handles this case with default header values.

Internal server error
*/
type UpdateMetadataInternalServerError struct {
}

func (o *UpdateMetadataInternalServerError) Error() string {
	return fmt.Sprintf("[POST /update][%d] updateMetadataInternalServerError ", 500)
}

func (o *UpdateMetadataInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
