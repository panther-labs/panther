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
	"testing"
	"time"

	"github.com/google/go-github/github"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
	"github.com/panther-labs/panther/internal/log_analysis/managedschemas"
)

func TestManagedSchemasUpdates(t *testing.T) {
	// Skip until we can mock http client for github
	t.Skip()

	db := &InMemDB{}
	_, _ = db.PutSchema(context.Background(), "AWS.CloudTrail", &SchemaRecord{
		Name:         "AWS.CloudTrail",
		Revision:     1,
		Release:      "v0.0.0-test",
		UpdatedAt:    time.Now(),
		CreatedAt:    time.Now(),
		Managed:      true,
		Disabled:     false,
		Description:  "",
		ReferenceURL: "",
		Spec:         "version: 0",
	})
	api := LogTypesAPI{
		Database: db,
		UpdateDataCatalog: func(_ context.Context, _ string, _, _ []logschema.FieldSchema) error {
			return nil
		},
		LogTypesInUse: func(_ context.Context) ([]string, error) {
			return nil, nil
		},
		ManagedSchemas: &managedschemas.GitHubRepository{
			Repo:   "panther-analysis",
			Owner:  "panther-labs",
			Client: github.NewClient(nil),
		},
	}
	{
		reply, err := api.ListManagedSchemaUpdates(context.Background(), &ListManagedSchemaUpdatesInput{})
		require.NoError(t, err)
		require.NotNil(t, reply)
		require.NotEmpty(t, reply.Releases)
	}

	{
		reply, err := api.UpdateManagedSchemas(context.Background(), &UpdateManagedSchemasInput{
			Release:     "v0.15.0",
			ManifestURL: "https://github.com/panther-labs/panther-analysis/releases/download/v1.15.0/managed-schemas.zip",
		})
		require.NoError(t, err)
		require.NotNil(t, reply)
	}
}
