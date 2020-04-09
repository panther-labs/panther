// Code generated by go-swagger; DO NOT EDIT.

// Panther is a Cloud-Native SIEM for the Modern Security Team.
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

	"github.com/panther-labs/panther/api/gateway/analysis/models"
)

// ListPoliciesReader is a Reader for the ListPolicies structure.
type ListPoliciesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListPoliciesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListPoliciesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewListPoliciesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewListPoliciesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewListPoliciesOK creates a ListPoliciesOK with default headers values
func NewListPoliciesOK() *ListPoliciesOK {
	return &ListPoliciesOK{}
}

/*ListPoliciesOK handles this case with default header values.

OK
*/
type ListPoliciesOK struct {
	Payload *models.PolicyList
}

func (o *ListPoliciesOK) Error() string {
	return fmt.Sprintf("[GET /list][%d] listPoliciesOK  %+v", 200, o.Payload)
}

func (o *ListPoliciesOK) GetPayload() *models.PolicyList {
	return o.Payload
}

func (o *ListPoliciesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PolicyList)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListPoliciesBadRequest creates a ListPoliciesBadRequest with default headers values
func NewListPoliciesBadRequest() *ListPoliciesBadRequest {
	return &ListPoliciesBadRequest{}
}

/*ListPoliciesBadRequest handles this case with default header values.

Bad request
*/
type ListPoliciesBadRequest struct {
	Payload *models.Error
}

func (o *ListPoliciesBadRequest) Error() string {
	return fmt.Sprintf("[GET /list][%d] listPoliciesBadRequest  %+v", 400, o.Payload)
}

func (o *ListPoliciesBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListPoliciesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListPoliciesInternalServerError creates a ListPoliciesInternalServerError with default headers values
func NewListPoliciesInternalServerError() *ListPoliciesInternalServerError {
	return &ListPoliciesInternalServerError{}
}

/*ListPoliciesInternalServerError handles this case with default header values.

Internal server error
*/
type ListPoliciesInternalServerError struct {
}

func (o *ListPoliciesInternalServerError) Error() string {
	return fmt.Sprintf("[GET /list][%d] listPoliciesInternalServerError ", 500)
}

func (o *ListPoliciesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
