package logtypesapi

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

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"golang.org/x/mod/semver"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
	"github.com/panther-labs/panther/internal/log_analysis/managedschemas"
)

type ListManagedSchemaUpdatesInput struct{}

type ListManagedSchemaUpdatesOutput struct {
	Releases *[]managedschemas.Release `json:"releases,omitempty" description:"Available release updates"`
	Error    *APIError                 `json:"error,omitempty" description:"An error that occurred while fetching the record"`
}

// nolint:lll
func (api *LogTypesAPI) ListManagedSchemaUpdates(ctx context.Context, _ *ListManagedSchemaUpdatesInput) (*ListManagedSchemaUpdatesOutput, error) {
	sinceTag, err := scanManagedSchemasMinRelease(ctx, api.Database)
	if err != nil {
		return nil, err
	}

	releases, err := api.ManagedSchemas.ReleaseFeed(ctx, sinceTag)
	if err != nil {
		return nil, err
	}
	if releases == nil {
		releases = []managedschemas.Release{}
	}
	return &ListManagedSchemaUpdatesOutput{
		Releases: &releases,
	}, nil
}

func scanManagedSchemasMinRelease(ctx context.Context, db SchemaDatabase) (string, error) {
	// Scan records for earliest release
	min := ""
	scan := func(r *SchemaRecord) bool {
		if r.IsManaged() && semver.IsValid(r.Release) {
			switch {
			case min == "":
				min = r.Release
			case semver.Compare(r.Release, min) == -1:
				min = r.Release
			}
		}
		return true
	}
	if err := db.ScanSchemas(ctx, scan); err != nil {
		return "", err
	}
	return min, nil
}

type UpdateManagedSchemasInput struct {
	Release     string `json:"release" validate:"required" description:"The release of the schema"`
	ManifestURL string `json:"manifestURL,omitempty" validate:"omitempty,url" description:"The URL to download the manifest archive from"`
}

type UpdateManagedSchemasOutput struct {
	Records []*SchemaRecord `json:"records"`
	Error   *APIError       `json:"error,omitempty" description:"An error that occurred while fetching the record"`
}

func (api *LogTypesAPI) UpdateManagedSchemas(ctx context.Context, input *UpdateManagedSchemasInput) (*UpdateManagedSchemasOutput, error) {
	entries, err := loadManifest(ctx, input.Release, input.ManifestURL)

	if err != nil {
		return nil, err
	}

	records := make([]*SchemaRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.Release != input.Release {
			return nil, errors.Errorf("invalid manifest entry %s", entry.Name)
		}
		record, err := api.updateManagedSchema(ctx, entry)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	return &UpdateManagedSchemasOutput{
		Records: records,
	}, nil
}

func loadManifest(ctx context.Context, release, manifestURL string) ([]managedschemas.ManifestEntry, error) {
	// Avoid calling github when the release is the embedded minimum release.
	// This ensures deployments succeed regardless of GitHub API availability.
	if release == managedschemas.ReleaseVersion {
		return managedschemas.LoadDefaultManifest()
	}
	return managedschemas.LoadReleaseManifestFromURL(ctx, manifestURL)
}

func (api *LogTypesAPI) updateManagedSchema(ctx context.Context, entry managedschemas.ManifestEntry) (*SchemaRecord, error) {
	schema, err := buildAndValidateManagedSchema(entry)
	if err != nil {
		return nil, err
	}
	record, err := api.Database.GetSchema(ctx, entry.Name, 0)
	if err != nil {
		return nil, err
	}
	rev := int64(1)
	if record != nil {
		if !record.IsManaged() {
			return nil, NewAPIError(ErrAlreadyExists, fmt.Sprintf("record %q exists and is not managed by Panther", entry.Name))
		}
		if semver.Compare(record.Release, entry.Release) != -1 {
			return record, nil
		}
		rev = record.Revision + 1
		// TODO: check update compatibility
	}
	return api.Database.UpdateManagedSchema(ctx, entry.Name, rev, entry.Release, SchemaUpdate{
		Description:  schema.Description,
		ReferenceURL: schema.ReferenceURL,
		Spec:         entry.Spec,
	})
}

func buildAndValidateManagedSchema(entry managedschemas.ManifestEntry) (*logschema.Schema, error) {
	schema, err := buildSchema(entry.Spec)
	if err != nil {
		return nil, errors.Wrapf(err, "managed schema entry %q in release %q has invalid YAML syntax", entry.Name, entry.Release)
	}
	if err := checkSchema(entry.Name, schema); err != nil {
		return nil, errors.Wrapf(err, "managed schema entry %q in release %q is not valid", entry.Name, entry.Release)
	}
	return schema, nil
}
