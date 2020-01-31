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
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/swag"

	strfmt "github.com/go-openapi/strfmt"
)

// NewListResourcesParams creates a new ListResourcesParams object
// with the default values initialized.
func NewListResourcesParams() *ListResourcesParams {
	var (
		pageDefault     = int64(1)
		pageSizeDefault = int64(25)
		sortByDefault   = string("id")
		sortDirDefault  = string("ascending")
	)
	return &ListResourcesParams{
		Page:     &pageDefault,
		PageSize: &pageSizeDefault,
		SortBy:   &sortByDefault,
		SortDir:  &sortDirDefault,

		timeout: cr.DefaultTimeout,
	}
}

// NewListResourcesParamsWithTimeout creates a new ListResourcesParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewListResourcesParamsWithTimeout(timeout time.Duration) *ListResourcesParams {
	var (
		pageDefault     = int64(1)
		pageSizeDefault = int64(25)
		sortByDefault   = string("id")
		sortDirDefault  = string("ascending")
	)
	return &ListResourcesParams{
		Page:     &pageDefault,
		PageSize: &pageSizeDefault,
		SortBy:   &sortByDefault,
		SortDir:  &sortDirDefault,

		timeout: timeout,
	}
}

// NewListResourcesParamsWithContext creates a new ListResourcesParams object
// with the default values initialized, and the ability to set a context for a request
func NewListResourcesParamsWithContext(ctx context.Context) *ListResourcesParams {
	var (
		pageDefault     = int64(1)
		pageSizeDefault = int64(25)
		sortByDefault   = string("id")
		sortDirDefault  = string("ascending")
	)
	return &ListResourcesParams{
		Page:     &pageDefault,
		PageSize: &pageSizeDefault,
		SortBy:   &sortByDefault,
		SortDir:  &sortDirDefault,

		Context: ctx,
	}
}

// NewListResourcesParamsWithHTTPClient creates a new ListResourcesParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewListResourcesParamsWithHTTPClient(client *http.Client) *ListResourcesParams {
	var (
		pageDefault     = int64(1)
		pageSizeDefault = int64(25)
		sortByDefault   = string("id")
		sortDirDefault  = string("ascending")
	)
	return &ListResourcesParams{
		Page:       &pageDefault,
		PageSize:   &pageSizeDefault,
		SortBy:     &sortByDefault,
		SortDir:    &sortDirDefault,
		HTTPClient: client,
	}
}

/*ListResourcesParams contains all the parameters to send to the API endpoint
for the list resources operation typically these are written to a http.Request
*/
type ListResourcesParams struct {

	/*ComplianceStatus
	  Only include resources with a specific compliance status

	*/
	ComplianceStatus *string
	/*Deleted
	  Only include resources which are or are not deleted

	*/
	Deleted *bool
	/*Fields
	  Resource fields to select (default - all except attributes)

	*/
	Fields []string
	/*IDContains
	  Only include resources whose ID contains this URL-encoded substring (case-insensitive)

	*/
	IDContains *string
	/*IntegrationID
	  Only include resources from this source integration

	*/
	IntegrationID *string
	/*IntegrationType
	  Only include resources from this integration type

	*/
	IntegrationType *string
	/*Page
	  Which page of results to retrieve

	*/
	Page *int64
	/*PageSize
	  Number of items in each page of results

	*/
	PageSize *int64
	/*SortBy
	  Name of the field to sort by

	*/
	SortBy *string
	/*SortDir
	  Sort direction

	*/
	SortDir *string
	/*Types
	  Only include resources which match one of these types

	*/
	Types []string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the list resources params
func (o *ListResourcesParams) WithTimeout(timeout time.Duration) *ListResourcesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list resources params
func (o *ListResourcesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list resources params
func (o *ListResourcesParams) WithContext(ctx context.Context) *ListResourcesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list resources params
func (o *ListResourcesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list resources params
func (o *ListResourcesParams) WithHTTPClient(client *http.Client) *ListResourcesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list resources params
func (o *ListResourcesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithComplianceStatus adds the complianceStatus to the list resources params
func (o *ListResourcesParams) WithComplianceStatus(complianceStatus *string) *ListResourcesParams {
	o.SetComplianceStatus(complianceStatus)
	return o
}

// SetComplianceStatus adds the complianceStatus to the list resources params
func (o *ListResourcesParams) SetComplianceStatus(complianceStatus *string) {
	o.ComplianceStatus = complianceStatus
}

// WithDeleted adds the deleted to the list resources params
func (o *ListResourcesParams) WithDeleted(deleted *bool) *ListResourcesParams {
	o.SetDeleted(deleted)
	return o
}

// SetDeleted adds the deleted to the list resources params
func (o *ListResourcesParams) SetDeleted(deleted *bool) {
	o.Deleted = deleted
}

// WithFields adds the fields to the list resources params
func (o *ListResourcesParams) WithFields(fields []string) *ListResourcesParams {
	o.SetFields(fields)
	return o
}

// SetFields adds the fields to the list resources params
func (o *ListResourcesParams) SetFields(fields []string) {
	o.Fields = fields
}

// WithIDContains adds the iDContains to the list resources params
func (o *ListResourcesParams) WithIDContains(iDContains *string) *ListResourcesParams {
	o.SetIDContains(iDContains)
	return o
}

// SetIDContains adds the idContains to the list resources params
func (o *ListResourcesParams) SetIDContains(iDContains *string) {
	o.IDContains = iDContains
}

// WithIntegrationID adds the integrationID to the list resources params
func (o *ListResourcesParams) WithIntegrationID(integrationID *string) *ListResourcesParams {
	o.SetIntegrationID(integrationID)
	return o
}

// SetIntegrationID adds the integrationId to the list resources params
func (o *ListResourcesParams) SetIntegrationID(integrationID *string) {
	o.IntegrationID = integrationID
}

// WithIntegrationType adds the integrationType to the list resources params
func (o *ListResourcesParams) WithIntegrationType(integrationType *string) *ListResourcesParams {
	o.SetIntegrationType(integrationType)
	return o
}

// SetIntegrationType adds the integrationType to the list resources params
func (o *ListResourcesParams) SetIntegrationType(integrationType *string) {
	o.IntegrationType = integrationType
}

// WithPage adds the page to the list resources params
func (o *ListResourcesParams) WithPage(page *int64) *ListResourcesParams {
	o.SetPage(page)
	return o
}

// SetPage adds the page to the list resources params
func (o *ListResourcesParams) SetPage(page *int64) {
	o.Page = page
}

// WithPageSize adds the pageSize to the list resources params
func (o *ListResourcesParams) WithPageSize(pageSize *int64) *ListResourcesParams {
	o.SetPageSize(pageSize)
	return o
}

// SetPageSize adds the pageSize to the list resources params
func (o *ListResourcesParams) SetPageSize(pageSize *int64) {
	o.PageSize = pageSize
}

// WithSortBy adds the sortBy to the list resources params
func (o *ListResourcesParams) WithSortBy(sortBy *string) *ListResourcesParams {
	o.SetSortBy(sortBy)
	return o
}

// SetSortBy adds the sortBy to the list resources params
func (o *ListResourcesParams) SetSortBy(sortBy *string) {
	o.SortBy = sortBy
}

// WithSortDir adds the sortDir to the list resources params
func (o *ListResourcesParams) WithSortDir(sortDir *string) *ListResourcesParams {
	o.SetSortDir(sortDir)
	return o
}

// SetSortDir adds the sortDir to the list resources params
func (o *ListResourcesParams) SetSortDir(sortDir *string) {
	o.SortDir = sortDir
}

// WithTypes adds the types to the list resources params
func (o *ListResourcesParams) WithTypes(types []string) *ListResourcesParams {
	o.SetTypes(types)
	return o
}

// SetTypes adds the types to the list resources params
func (o *ListResourcesParams) SetTypes(types []string) {
	o.Types = types
}

// WriteToRequest writes these params to a swagger request
func (o *ListResourcesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.ComplianceStatus != nil {

		// query param complianceStatus
		var qrComplianceStatus string
		if o.ComplianceStatus != nil {
			qrComplianceStatus = *o.ComplianceStatus
		}
		qComplianceStatus := qrComplianceStatus
		if qComplianceStatus != "" {
			if err := r.SetQueryParam("complianceStatus", qComplianceStatus); err != nil {
				return err
			}
		}

	}

	if o.Deleted != nil {

		// query param deleted
		var qrDeleted bool
		if o.Deleted != nil {
			qrDeleted = *o.Deleted
		}
		qDeleted := swag.FormatBool(qrDeleted)
		if qDeleted != "" {
			if err := r.SetQueryParam("deleted", qDeleted); err != nil {
				return err
			}
		}

	}

	valuesFields := o.Fields

	joinedFields := swag.JoinByFormat(valuesFields, "csv")
	// query array param fields
	if err := r.SetQueryParam("fields", joinedFields...); err != nil {
		return err
	}

	if o.IDContains != nil {

		// query param idContains
		var qrIDContains string
		if o.IDContains != nil {
			qrIDContains = *o.IDContains
		}
		qIDContains := qrIDContains
		if qIDContains != "" {
			if err := r.SetQueryParam("idContains", qIDContains); err != nil {
				return err
			}
		}

	}

	if o.IntegrationID != nil {

		// query param integrationId
		var qrIntegrationID string
		if o.IntegrationID != nil {
			qrIntegrationID = *o.IntegrationID
		}
		qIntegrationID := qrIntegrationID
		if qIntegrationID != "" {
			if err := r.SetQueryParam("integrationId", qIntegrationID); err != nil {
				return err
			}
		}

	}

	if o.IntegrationType != nil {

		// query param integrationType
		var qrIntegrationType string
		if o.IntegrationType != nil {
			qrIntegrationType = *o.IntegrationType
		}
		qIntegrationType := qrIntegrationType
		if qIntegrationType != "" {
			if err := r.SetQueryParam("integrationType", qIntegrationType); err != nil {
				return err
			}
		}

	}

	if o.Page != nil {

		// query param page
		var qrPage int64
		if o.Page != nil {
			qrPage = *o.Page
		}
		qPage := swag.FormatInt64(qrPage)
		if qPage != "" {
			if err := r.SetQueryParam("page", qPage); err != nil {
				return err
			}
		}

	}

	if o.PageSize != nil {

		// query param pageSize
		var qrPageSize int64
		if o.PageSize != nil {
			qrPageSize = *o.PageSize
		}
		qPageSize := swag.FormatInt64(qrPageSize)
		if qPageSize != "" {
			if err := r.SetQueryParam("pageSize", qPageSize); err != nil {
				return err
			}
		}

	}

	if o.SortBy != nil {

		// query param sortBy
		var qrSortBy string
		if o.SortBy != nil {
			qrSortBy = *o.SortBy
		}
		qSortBy := qrSortBy
		if qSortBy != "" {
			if err := r.SetQueryParam("sortBy", qSortBy); err != nil {
				return err
			}
		}

	}

	if o.SortDir != nil {

		// query param sortDir
		var qrSortDir string
		if o.SortDir != nil {
			qrSortDir = *o.SortDir
		}
		qSortDir := qrSortDir
		if qSortDir != "" {
			if err := r.SetQueryParam("sortDir", qSortDir); err != nil {
				return err
			}
		}

	}

	valuesTypes := o.Types

	joinedTypes := swag.JoinByFormat(valuesTypes, "csv")
	// query array param types
	if err := r.SetQueryParam("types", joinedTypes...); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
