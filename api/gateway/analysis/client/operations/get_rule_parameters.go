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
	"context"
	"net/http"
	"time"
	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewGetRuleParams creates a new GetRuleParams object
// with the default values initialized.
func NewGetRuleParams() *GetRuleParams {
	var ()
	return &GetRuleParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetRuleParamsWithTimeout creates a new GetRuleParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetRuleParamsWithTimeout(timeout time.Duration) *GetRuleParams {
	var ()
	return &GetRuleParams{

		timeout: timeout,
	}
}

// NewGetRuleParamsWithContext creates a new GetRuleParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetRuleParamsWithContext(ctx context.Context) *GetRuleParams {
	var ()
	return &GetRuleParams{

		Context: ctx,
	}
}

// NewGetRuleParamsWithHTTPClient creates a new GetRuleParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetRuleParamsWithHTTPClient(client *http.Client) *GetRuleParams {
	var ()
	return &GetRuleParams{
		HTTPClient: client,
	}
}

/*GetRuleParams contains all the parameters to send to the API endpoint
for the get rule operation typically these are written to a http.Request
*/
type GetRuleParams struct {

	/*RuleID
	  Unique ASCII rule identifier

	*/
	RuleID string
	/*VersionID
	  The version of the analysis to retrieve

	*/
	VersionID *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get rule params
func (o *GetRuleParams) WithTimeout(timeout time.Duration) *GetRuleParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get rule params
func (o *GetRuleParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get rule params
func (o *GetRuleParams) WithContext(ctx context.Context) *GetRuleParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get rule params
func (o *GetRuleParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get rule params
func (o *GetRuleParams) WithHTTPClient(client *http.Client) *GetRuleParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get rule params
func (o *GetRuleParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithRuleID adds the ruleID to the get rule params
func (o *GetRuleParams) WithRuleID(ruleID string) *GetRuleParams {
	o.SetRuleID(ruleID)
	return o
}

// SetRuleID adds the ruleId to the get rule params
func (o *GetRuleParams) SetRuleID(ruleID string) {
	o.RuleID = ruleID
}

// WithVersionID adds the versionID to the get rule params
func (o *GetRuleParams) WithVersionID(versionID *string) *GetRuleParams {
	o.SetVersionID(versionID)
	return o
}

// SetVersionID adds the versionId to the get rule params
func (o *GetRuleParams) SetVersionID(versionID *string) {
	o.VersionID = versionID
}

// WriteToRequest writes these params to a swagger request
func (o *GetRuleParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param ruleId
	qrRuleID := o.RuleID
	qRuleID := qrRuleID
	if qRuleID != "" {
		if err := r.SetQueryParam("ruleId", qRuleID); err != nil {
			return err
		}
	}

	if o.VersionID != nil {

		// query param versionId
		var qrVersionID string
		if o.VersionID != nil {
			qrVersionID = *o.VersionID
		}
		qVersionID := qrVersionID
		if qVersionID != "" {
			if err := r.SetQueryParam("versionId", qVersionID); err != nil {
				return err
			}
		}

	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
