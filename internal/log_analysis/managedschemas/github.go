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
	"sort"

	"github.com/google/go-github/github"
	"golang.org/x/mod/semver"
)

var _ ReleaseFeeder = (*GitHubRepository)(nil)

// GitHubRepository fetches release feeds using GitHub Releases API
type GitHubRepository struct {
	Repo   string
	Owner  string
	Client *github.Client
}

const githubAssetName = "managed-schemas.zip"

// ReleaseFeed implements ReleaseFeeder interface
func (p *GitHubRepository) ReleaseFeed(ctx context.Context, sinceTag string) ([]Release, error) {
	latestReleases, _, err := p.Client.Repositories.ListReleases(ctx, p.Owner, p.Repo, &github.ListOptions{})
	if err != nil {
		return nil, err
	}
	feed := make([]Release, 0, len(latestReleases))
	for _, rel := range latestReleases {
		r := fromGitHubRelease(rel, githubAssetName)
		if !r.IsValid() {
			continue
		}
		feed = append(feed, r)
	}
	// Sort by tag
	sort.Sort(ReleaseFeed(feed))
	if !semver.IsValid(sinceTag) {
		return feed, nil
	}
	for i := range feed {
		if semver.Compare(sinceTag, feed[i].Tag) == 1 {
			return feed[i:], nil
		}
	}
	return []Release{}, nil
}

func fromGitHubRelease(rel *github.RepositoryRelease, assetName string) Release {
	out := Release{}
	if rel.TagName != nil {
		out.Tag = *rel.TagName
	}
	if rel.Body != nil {
		out.Description = *rel.Body
	}
	if asset := findAsset(rel, assetName); asset != nil && asset.BrowserDownloadURL != nil {
		out.ManifestURL = *asset.BrowserDownloadURL
	}
	return out
}

func findAsset(r *github.RepositoryRelease, assetName string) *github.ReleaseAsset {
	for i := range r.Assets {
		asset := &r.Assets[i]
		if asset.Name != nil && *asset.Name == assetName {
			return asset
		}
	}
	return nil
}
