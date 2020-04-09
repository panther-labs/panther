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

	"github.com/panther-labs/panther/api/gateway/compliance/models"
)

// GetOrgOverviewReader is a Reader for the GetOrgOverview structure.
type GetOrgOverviewReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetOrgOverviewReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetOrgOverviewOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetOrgOverviewBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetOrgOverviewInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewGetOrgOverviewOK creates a GetOrgOverviewOK with default headers values
func NewGetOrgOverviewOK() *GetOrgOverviewOK {
	return &GetOrgOverviewOK{}
}

/*GetOrgOverviewOK handles this case with default header values.

OK
*/
type GetOrgOverviewOK struct {
	Payload *models.OrgSummary
}

func (o *GetOrgOverviewOK) Error() string {
	return fmt.Sprintf("[GET /org-overview][%d] getOrgOverviewOK  %+v", 200, o.Payload)
}

func (o *GetOrgOverviewOK) GetPayload() *models.OrgSummary {
	return o.Payload
}

func (o *GetOrgOverviewOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OrgSummary)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOrgOverviewBadRequest creates a GetOrgOverviewBadRequest with default headers values
func NewGetOrgOverviewBadRequest() *GetOrgOverviewBadRequest {
	return &GetOrgOverviewBadRequest{}
}

/*GetOrgOverviewBadRequest handles this case with default header values.

Bad request
*/
type GetOrgOverviewBadRequest struct {
	Payload *models.Error
}

func (o *GetOrgOverviewBadRequest) Error() string {
	return fmt.Sprintf("[GET /org-overview][%d] getOrgOverviewBadRequest  %+v", 400, o.Payload)
}

func (o *GetOrgOverviewBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetOrgOverviewBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetOrgOverviewInternalServerError creates a GetOrgOverviewInternalServerError with default headers values
func NewGetOrgOverviewInternalServerError() *GetOrgOverviewInternalServerError {
	return &GetOrgOverviewInternalServerError{}
}

/*GetOrgOverviewInternalServerError handles this case with default header values.

Internal server error
*/
type GetOrgOverviewInternalServerError struct {
}

func (o *GetOrgOverviewInternalServerError) Error() string {
	return fmt.Sprintf("[GET /org-overview][%d] getOrgOverviewInternalServerError ", 500)
}

func (o *GetOrgOverviewInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
