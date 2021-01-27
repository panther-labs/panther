package handlers

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
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/google/go-github/github"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/stringset"
)

type GithubClient struct {
	Github     *github.Client
	HTTPClient *http.Client
}

func NewGithubClient() *GithubClient {
	githubClnt := github.NewClient(nil)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		},
	}
	httpClnt := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
	return &GithubClient{
		Github:     githubClnt,
		HTTPClient: httpClnt,
	}
}

func (c *GithubClient) DownloadGithubReleaseAssets(owner string, repository string,
	version models.Version, assets []string) (assetData map[string][]byte, err error) {

	// setup var to return, a map of asset name to asset raw data
	assetData = make(map[string][]byte)
	// First, get all of the release data
	release, _, err := c.Github.Repositories.GetRelease(context.Background(), owner, repository, version.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to download release from repo %s", repository)
	}
	// retrieve the assets passed in
	for _, releaseAsset := range release.Assets {
		var rawData []byte
		if stringset.Contains(assets, aws.StringValue(releaseAsset.Name)) {
			rawData, err = downloadGithubAsset(c, owner, repository, *releaseAsset.ID)
			if err != nil {
				// If we failed to download an asset, return the error
				return nil, err
			}
			assetData[aws.StringValue(releaseAsset.Name)] = rawData
		}
	}
	return assetData, nil
}

func (c *GithubClient) ListAvailableGithubReleases(owner string, repository string) ([]*github.RepositoryRelease, error) {
	// Setup options
	// By default returns all releases, paged at 100 releases at a time
	opt := &github.ListOptions{}
	var allReleases []*github.RepositoryRelease
	for {
		releases, response, err := c.Github.Repositories.ListReleases(context.Background(), owner, repository, opt)
		if err != nil {
			return nil, err
		}
		allReleases = append(allReleases, releases...)
		if response.NextPage == 0 {
			break
		}
		opt.Page = response.NextPage
	}
	return allReleases, nil
}

func downloadGithubAsset(client *GithubClient, owner string, repository string, id int64) ([]byte, error) {
	rawAsset, url, err := client.Github.Repositories.DownloadReleaseAsset(context.TODO(), owner, repository, id)
	if err != nil {
		return nil, fmt.Errorf("failed to download release asset from repo %s", repository)
	}
	// download the raw data
	var body []byte
	if rawAsset != nil {
		defer rawAsset.Close()
		body, err = ioutil.ReadAll(rawAsset)
	} else if url != "" {
		body, err = downloadURL(client, url)
	}
	return body, err
}

func downloadURL(client *GithubClient, url string) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("url is not https: %v", url)
	}
	response, err := client.HTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to GET %s: %v", url, err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to download %s: %v", url, err)
	}
	return body, nil
}
