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
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/panther-labs/panther/api/gateway/analysis/models"
)

// NewSuppressParams creates a new SuppressParams object
// with the default values initialized.
func NewSuppressParams() *SuppressParams {
	var ()
	return &SuppressParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewSuppressParamsWithTimeout creates a new SuppressParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewSuppressParamsWithTimeout(timeout time.Duration) *SuppressParams {
	var ()
	return &SuppressParams{

		timeout: timeout,
	}
}

// NewSuppressParamsWithContext creates a new SuppressParams object
// with the default values initialized, and the ability to set a context for a request
func NewSuppressParamsWithContext(ctx context.Context) *SuppressParams {
	var ()
	return &SuppressParams{

		Context: ctx,
	}
}

// NewSuppressParamsWithHTTPClient creates a new SuppressParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewSuppressParamsWithHTTPClient(client *http.Client) *SuppressParams {
	var ()
	return &SuppressParams{
		HTTPClient: client,
	}
}

/*SuppressParams contains all the parameters to send to the API endpoint
for the suppress operation typically these are written to a http.Request
*/
type SuppressParams struct {

	/*Body*/
	Body *models.Suppress

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the suppress params
func (o *SuppressParams) WithTimeout(timeout time.Duration) *SuppressParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the suppress params
func (o *SuppressParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the suppress params
func (o *SuppressParams) WithContext(ctx context.Context) *SuppressParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the suppress params
func (o *SuppressParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the suppress params
func (o *SuppressParams) WithHTTPClient(client *http.Client) *SuppressParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the suppress params
func (o *SuppressParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the suppress params
func (o *SuppressParams) WithBody(body *models.Suppress) *SuppressParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the suppress params
func (o *SuppressParams) SetBody(body *models.Suppress) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *SuppressParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
