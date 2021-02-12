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
	"archive/zip"
	"bytes"
	"context"
	"io"
	"io/ioutil"

	"golang.org/x/mod/semver"
	yaml3 "gopkg.in/yaml.v3"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
)

// ReleaseFeeder provides a feed of releases since a specific version tag
type ReleaseFeeder interface {
	ReleaseFeed(ctx context.Context, sinceTag string) ([]Release, error)
}

// Release describes a managed schema release
type Release struct {
	Tag         string `json:"tag"`
	Description string `json:"description"`
	ManifestURL string `json:"manifestURL"`
}

// ReleaseFeed is a list of managed schema releases
type ReleaseFeed []Release

// ManifestEntry describes a managed schema entry from a specific release
type ManifestEntry struct {
	Release string
	Name    string
	Spec    string
}

// IsValid checks that a release has a valid version and points to a manifest file
func (r *Release) IsValid() bool {
	return semver.IsValid(r.Tag) && r.ManifestURL != ""
}

// Valid filters a release feed keeping only valid entries
func (f ReleaseFeed) Valid() ReleaseFeed {
	if f == nil {
		return nil
	}
	feed := make([]Release, 0, len(f))
	for _, rel := range f {
		if !rel.IsValid() {
			continue
		}
		feed = append(feed, rel)
	}
	return feed
}

// Len implements sort.Interface
func (f ReleaseFeed) Len() int {
	return len(f)
}

// Swap implements sort.Interface
func (f ReleaseFeed) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
}

// Less implements sort.Interface
func (f ReleaseFeed) Less(i, j int) bool {
	a, b := f[i].Tag, f[j].Tag
	return semver.Compare(a, b) == -1
}

func unzipFile(z *zip.Reader, filename string) ([]byte, error) {
	file := findArchiveFile(z, filename)
	if file == nil {
		return nil, nil
	}
	r, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return ioutil.ReadAll(r)
}

func findArchiveFile(z *zip.Reader, name string) *zip.File {
	for _, f := range z.File {
		if f.Name == name {
			return f
		}
	}
	return nil
}

// ReadYAMLManifest reads entries from a `manifest.yml` file
func ReadYAMLManifest(release string, r io.Reader) ([]ManifestEntry, error) {
	dec := yaml3.NewDecoder(r)
	var manifest []ManifestEntry
	for {
		node := yaml3.Node{}
		if err := dec.Decode(&node); err != nil {
			if err == io.EOF {
				return manifest, nil
			}
			return nil, err
		}
		spec, err := yaml3.Marshal(&node)
		if err != nil {
			return nil, err
		}
		schema := logschema.Schema{}
		if err := node.Decode(&schema); err != nil {
			return nil, err
		}
		manifest = append(manifest, ManifestEntry{
			Release: release,
			Name:    schema.Schema,
			Spec:    string(spec),
		})
	}
}

// LoadReleaseManifestFromURL fetches a release archive from a URL and reads manifest entries.
func LoadReleaseManifestFromURL(ctx context.Context, manifestURL string) ([]ManifestEntry, error) {
	manifestArchive, err := DownloadFile(ctx, nil, manifestURL)
	if err != nil {
		return nil, err
	}
	zipArchive, err := zip.NewReader(bytes.NewReader(manifestArchive), int64(len(manifestURL)))
	if err != nil {
		return nil, err
	}
	manifestFile, err := unzipFile(zipArchive, "manifest.yml")
	if err != nil {
		return nil, err
	}
	if manifestFile == nil {
		return nil, nil
	}
	releaseVersion := zipArchive.Comment
	return ReadYAMLManifest(releaseVersion, bytes.NewReader(manifestFile))
}

func MustLoadDefaultManifest() []ManifestEntry {
	entries, err := LoadDefaultManifest()
	if err != nil {
		panic("failed to load manifest: " + err.Error())
	}
	return entries
}

func LoadDefaultManifest() ([]ManifestEntry, error) {
	data, err := Asset("manifest.yml")
	if err != nil {
		return nil, err
	}
	return ReadYAMLManifest(ReleaseVersion, bytes.NewReader(data))
}
