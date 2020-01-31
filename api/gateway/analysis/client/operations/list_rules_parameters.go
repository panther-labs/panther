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

// NewListRulesParams creates a new ListRulesParams object
// with the default values initialized.
func NewListRulesParams() *ListRulesParams {
	var (
		pageDefault     = int64(1)
		pageSizeDefault = int64(25)
		sortByDefault   = string("severity")
		sortDirDefault  = string("ascending")
	)
	return &ListRulesParams{
		Page:     &pageDefault,
		PageSize: &pageSizeDefault,
		SortBy:   &sortByDefault,
		SortDir:  &sortDirDefault,

		timeout: cr.DefaultTimeout,
	}
}

// NewListRulesParamsWithTimeout creates a new ListRulesParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewListRulesParamsWithTimeout(timeout time.Duration) *ListRulesParams {
	var (
		pageDefault     = int64(1)
		pageSizeDefault = int64(25)
		sortByDefault   = string("severity")
		sortDirDefault  = string("ascending")
	)
	return &ListRulesParams{
		Page:     &pageDefault,
		PageSize: &pageSizeDefault,
		SortBy:   &sortByDefault,
		SortDir:  &sortDirDefault,

		timeout: timeout,
	}
}

// NewListRulesParamsWithContext creates a new ListRulesParams object
// with the default values initialized, and the ability to set a context for a request
func NewListRulesParamsWithContext(ctx context.Context) *ListRulesParams {
	var (
		pageDefault     = int64(1)
		pageSizeDefault = int64(25)
		sortByDefault   = string("severity")
		sortDirDefault  = string("ascending")
	)
	return &ListRulesParams{
		Page:     &pageDefault,
		PageSize: &pageSizeDefault,
		SortBy:   &sortByDefault,
		SortDir:  &sortDirDefault,

		Context: ctx,
	}
}

// NewListRulesParamsWithHTTPClient creates a new ListRulesParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewListRulesParamsWithHTTPClient(client *http.Client) *ListRulesParams {
	var (
		pageDefault     = int64(1)
		pageSizeDefault = int64(25)
		sortByDefault   = string("severity")
		sortDirDefault  = string("ascending")
	)
	return &ListRulesParams{
		Page:       &pageDefault,
		PageSize:   &pageSizeDefault,
		SortBy:     &sortByDefault,
		SortDir:    &sortDirDefault,
		HTTPClient: client,
	}
}

/*ListRulesParams contains all the parameters to send to the API endpoint
for the list rules operation typically these are written to a http.Request
*/
type ListRulesParams struct {

	/*Enabled
	  Only include rules which are enabled or disabled

	*/
	Enabled *bool
	/*LogTypes
	  Only include rules which apply to one of these log types

	*/
	LogTypes []string
	/*NameContains
	  Only include rules whose ID or display name contains this substring (case-insensitive)

	*/
	NameContains *string
	/*Page
	  Which page of results to retrieve

	*/
	Page *int64
	/*PageSize
	  Number of items in each page of results

	*/
	PageSize *int64
	/*Severity
	  Only include policies with this severity

	*/
	Severity *string
	/*SortBy
	  Name of the field to sort by

	*/
	SortBy *string
	/*SortDir
	  Sort direction

	*/
	SortDir *string
	/*Tags
	  Only include policies with all of these tags (case-insensitive)

	*/
	Tags []string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the list rules params
func (o *ListRulesParams) WithTimeout(timeout time.Duration) *ListRulesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list rules params
func (o *ListRulesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list rules params
func (o *ListRulesParams) WithContext(ctx context.Context) *ListRulesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list rules params
func (o *ListRulesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list rules params
func (o *ListRulesParams) WithHTTPClient(client *http.Client) *ListRulesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list rules params
func (o *ListRulesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithEnabled adds the enabled to the list rules params
func (o *ListRulesParams) WithEnabled(enabled *bool) *ListRulesParams {
	o.SetEnabled(enabled)
	return o
}

// SetEnabled adds the enabled to the list rules params
func (o *ListRulesParams) SetEnabled(enabled *bool) {
	o.Enabled = enabled
}

// WithLogTypes adds the logTypes to the list rules params
func (o *ListRulesParams) WithLogTypes(logTypes []string) *ListRulesParams {
	o.SetLogTypes(logTypes)
	return o
}

// SetLogTypes adds the logTypes to the list rules params
func (o *ListRulesParams) SetLogTypes(logTypes []string) {
	o.LogTypes = logTypes
}

// WithNameContains adds the nameContains to the list rules params
func (o *ListRulesParams) WithNameContains(nameContains *string) *ListRulesParams {
	o.SetNameContains(nameContains)
	return o
}

// SetNameContains adds the nameContains to the list rules params
func (o *ListRulesParams) SetNameContains(nameContains *string) {
	o.NameContains = nameContains
}

// WithPage adds the page to the list rules params
func (o *ListRulesParams) WithPage(page *int64) *ListRulesParams {
	o.SetPage(page)
	return o
}

// SetPage adds the page to the list rules params
func (o *ListRulesParams) SetPage(page *int64) {
	o.Page = page
}

// WithPageSize adds the pageSize to the list rules params
func (o *ListRulesParams) WithPageSize(pageSize *int64) *ListRulesParams {
	o.SetPageSize(pageSize)
	return o
}

// SetPageSize adds the pageSize to the list rules params
func (o *ListRulesParams) SetPageSize(pageSize *int64) {
	o.PageSize = pageSize
}

// WithSeverity adds the severity to the list rules params
func (o *ListRulesParams) WithSeverity(severity *string) *ListRulesParams {
	o.SetSeverity(severity)
	return o
}

// SetSeverity adds the severity to the list rules params
func (o *ListRulesParams) SetSeverity(severity *string) {
	o.Severity = severity
}

// WithSortBy adds the sortBy to the list rules params
func (o *ListRulesParams) WithSortBy(sortBy *string) *ListRulesParams {
	o.SetSortBy(sortBy)
	return o
}

// SetSortBy adds the sortBy to the list rules params
func (o *ListRulesParams) SetSortBy(sortBy *string) {
	o.SortBy = sortBy
}

// WithSortDir adds the sortDir to the list rules params
func (o *ListRulesParams) WithSortDir(sortDir *string) *ListRulesParams {
	o.SetSortDir(sortDir)
	return o
}

// SetSortDir adds the sortDir to the list rules params
func (o *ListRulesParams) SetSortDir(sortDir *string) {
	o.SortDir = sortDir
}

// WithTags adds the tags to the list rules params
func (o *ListRulesParams) WithTags(tags []string) *ListRulesParams {
	o.SetTags(tags)
	return o
}

// SetTags adds the tags to the list rules params
func (o *ListRulesParams) SetTags(tags []string) {
	o.Tags = tags
}

// WriteToRequest writes these params to a swagger request
func (o *ListRulesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Enabled != nil {

		// query param enabled
		var qrEnabled bool
		if o.Enabled != nil {
			qrEnabled = *o.Enabled
		}
		qEnabled := swag.FormatBool(qrEnabled)
		if qEnabled != "" {
			if err := r.SetQueryParam("enabled", qEnabled); err != nil {
				return err
			}
		}

	}

	valuesLogTypes := o.LogTypes

	joinedLogTypes := swag.JoinByFormat(valuesLogTypes, "csv")
	// query array param logTypes
	if err := r.SetQueryParam("logTypes", joinedLogTypes...); err != nil {
		return err
	}

	if o.NameContains != nil {

		// query param nameContains
		var qrNameContains string
		if o.NameContains != nil {
			qrNameContains = *o.NameContains
		}
		qNameContains := qrNameContains
		if qNameContains != "" {
			if err := r.SetQueryParam("nameContains", qNameContains); err != nil {
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

	if o.Severity != nil {

		// query param severity
		var qrSeverity string
		if o.Severity != nil {
			qrSeverity = *o.Severity
		}
		qSeverity := qrSeverity
		if qSeverity != "" {
			if err := r.SetQueryParam("severity", qSeverity); err != nil {
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

	valuesTags := o.Tags

	joinedTags := swag.JoinByFormat(valuesTags, "csv")
	// query array param tags
	if err := r.SetQueryParam("tags", joinedTags...); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
