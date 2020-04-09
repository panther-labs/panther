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

// NewTestPolicyParams creates a new TestPolicyParams object
// with the default values initialized.
func NewTestPolicyParams() *TestPolicyParams {
	var ()
	return &TestPolicyParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewTestPolicyParamsWithTimeout creates a new TestPolicyParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewTestPolicyParamsWithTimeout(timeout time.Duration) *TestPolicyParams {
	var ()
	return &TestPolicyParams{

		timeout: timeout,
	}
}

// NewTestPolicyParamsWithContext creates a new TestPolicyParams object
// with the default values initialized, and the ability to set a context for a request
func NewTestPolicyParamsWithContext(ctx context.Context) *TestPolicyParams {
	var ()
	return &TestPolicyParams{

		Context: ctx,
	}
}

// NewTestPolicyParamsWithHTTPClient creates a new TestPolicyParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewTestPolicyParamsWithHTTPClient(client *http.Client) *TestPolicyParams {
	var ()
	return &TestPolicyParams{
		HTTPClient: client,
	}
}

/*TestPolicyParams contains all the parameters to send to the API endpoint
for the test policy operation typically these are written to a http.Request
*/
type TestPolicyParams struct {

	/*Body*/
	Body *models.TestPolicy

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the test policy params
func (o *TestPolicyParams) WithTimeout(timeout time.Duration) *TestPolicyParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the test policy params
func (o *TestPolicyParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the test policy params
func (o *TestPolicyParams) WithContext(ctx context.Context) *TestPolicyParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the test policy params
func (o *TestPolicyParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the test policy params
func (o *TestPolicyParams) WithHTTPClient(client *http.Client) *TestPolicyParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the test policy params
func (o *TestPolicyParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the test policy params
func (o *TestPolicyParams) WithBody(body *models.TestPolicy) *TestPolicyParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the test policy params
func (o *TestPolicyParams) SetBody(body *models.TestPolicy) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *TestPolicyParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
