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
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// NewGetOrgOverviewParams creates a new GetOrgOverviewParams object
// with the default values initialized.
func NewGetOrgOverviewParams() *GetOrgOverviewParams {
	var (
		limitTopFailingDefault = int64(10)
	)
	return &GetOrgOverviewParams{
		LimitTopFailing: &limitTopFailingDefault,

		timeout: cr.DefaultTimeout,
	}
}

// NewGetOrgOverviewParamsWithTimeout creates a new GetOrgOverviewParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetOrgOverviewParamsWithTimeout(timeout time.Duration) *GetOrgOverviewParams {
	var (
		limitTopFailingDefault = int64(10)
	)
	return &GetOrgOverviewParams{
		LimitTopFailing: &limitTopFailingDefault,

		timeout: timeout,
	}
}

// NewGetOrgOverviewParamsWithContext creates a new GetOrgOverviewParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetOrgOverviewParamsWithContext(ctx context.Context) *GetOrgOverviewParams {
	var (
		limitTopFailingDefault = int64(10)
	)
	return &GetOrgOverviewParams{
		LimitTopFailing: &limitTopFailingDefault,

		Context: ctx,
	}
}

// NewGetOrgOverviewParamsWithHTTPClient creates a new GetOrgOverviewParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetOrgOverviewParamsWithHTTPClient(client *http.Client) *GetOrgOverviewParams {
	var (
		limitTopFailingDefault = int64(10)
	)
	return &GetOrgOverviewParams{
		LimitTopFailing: &limitTopFailingDefault,
		HTTPClient:      client,
	}
}

/*GetOrgOverviewParams contains all the parameters to send to the API endpoint
for the get org overview operation typically these are written to a http.Request
*/
type GetOrgOverviewParams struct {

	/*LimitTopFailing
	  Upper bound on the number of top failing resources and policies returned

	*/
	LimitTopFailing *int64

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get org overview params
func (o *GetOrgOverviewParams) WithTimeout(timeout time.Duration) *GetOrgOverviewParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get org overview params
func (o *GetOrgOverviewParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get org overview params
func (o *GetOrgOverviewParams) WithContext(ctx context.Context) *GetOrgOverviewParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get org overview params
func (o *GetOrgOverviewParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get org overview params
func (o *GetOrgOverviewParams) WithHTTPClient(client *http.Client) *GetOrgOverviewParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get org overview params
func (o *GetOrgOverviewParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithLimitTopFailing adds the limitTopFailing to the get org overview params
func (o *GetOrgOverviewParams) WithLimitTopFailing(limitTopFailing *int64) *GetOrgOverviewParams {
	o.SetLimitTopFailing(limitTopFailing)
	return o
}

// SetLimitTopFailing adds the limitTopFailing to the get org overview params
func (o *GetOrgOverviewParams) SetLimitTopFailing(limitTopFailing *int64) {
	o.LimitTopFailing = limitTopFailing
}

// WriteToRequest writes these params to a swagger request
func (o *GetOrgOverviewParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.LimitTopFailing != nil {

		// query param limitTopFailing
		var qrLimitTopFailing int64
		if o.LimitTopFailing != nil {
			qrLimitTopFailing = *o.LimitTopFailing
		}
		qLimitTopFailing := swag.FormatInt64(qrLimitTopFailing)
		if qLimitTopFailing != "" {
			if err := r.SetQueryParam("limitTopFailing", qLimitTopFailing); err != nil {
				return err
			}
		}

	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
