package managedschemas

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

	"github.com/google/go-github/github"
	"github.com/stretchr/testify/require"
)

func TestGitHubRepository_ReleaseFeed(t *testing.T) {
	// Skip until we can mock http client for github
	t.Skip()

	assert := require.New(t)
	repo := GitHubRepository{
		Repo:   "panther-analysis",
		Owner:  "panther-labs",
		Client: github.NewClient(nil),
	}
	feed, err := repo.ReleaseFeed(context.Background(), "v0.0.0")
	assert.NoError(err)
	assert.NotEmpty(feed)
}
