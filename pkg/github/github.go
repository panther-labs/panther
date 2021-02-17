package github

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

	"github.com/panther-labs/panther/pkg/stringset"
)

var (
	defaultTimeout    = 10 * time.Second
	safeHTTPTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		},
	}
)

type Client struct {
	Github     *github.Client
	HTTPClient *http.Client
}

type Config struct {
	Owner      string
	Repository string
	Assets     []string
}

func NewClient(client *http.Client) *Client {
	if client == nil {
		client = &http.Client{
			Transport: safeHTTPTransport,
			Timeout:   defaultTimeout,
		}
	} else {
		if client.Transport == nil {
			client.Transport = safeHTTPTransport
		}
		if client.Timeout == 0 {
			client.Timeout = defaultTimeout
		}
	}
	githubClnt := github.NewClient(client)
	return &Client{
		Github:     githubClnt,
		HTTPClient: client,
	}
}

func NewConfig(owner string, repository string, assets []string) Config {
	return Config{
		Owner:      owner,
		Repository: repository,
		Assets:     assets,
	}
}

func (c *Client) DownloadGithubReleaseAssets(cxt context.Context, githubConfig Config,
	version int64) (assetData map[string][]byte, err error) {

	// setup var to return, a map of asset name to asset raw data
	assetData = make(map[string][]byte)
	// First, get all of the release data
	release, _, err := c.Github.Repositories.GetRelease(cxt, githubConfig.Owner, githubConfig.Repository, version)
	if err != nil {
		return nil, fmt.Errorf("failed to download release from repo %s", githubConfig.Repository)
	}
	// retrieve the assets passed in
	for _, releaseAsset := range release.Assets {
		var rawData []byte
		if stringset.Contains(githubConfig.Assets, aws.StringValue(releaseAsset.Name)) {
			rawData, err = downloadGithubAsset(cxt, c, githubConfig.Owner, githubConfig.Repository, *releaseAsset.ID)
			if err != nil {
				// If we failed to download an asset, return the error
				return nil, err
			}
			assetData[aws.StringValue(releaseAsset.Name)] = rawData
		}
	}
	return assetData, nil
}

func (c *Client) ListAvailableGithubReleases(cxt context.Context, githubConfig Config) ([]*github.RepositoryRelease, error) {
	// Note: github rate limits at 60 requests per hour. Use this function wisely and do not trigger by user page accesses
	// Setup options
	// By default returns all releases, paged at 100 releases at a time
	opt := &github.ListOptions{}
	// Only retrieve one page of 100 most recently published releases to prevent running into rate limits
	releases, _, err := c.Github.Repositories.ListReleases(cxt, githubConfig.Owner, githubConfig.Repository, opt)
	if err != nil {
		return nil, err
	}
	return releases, nil
}

func (c *Client) GetReleaseTagName(cxt context.Context, githubConfig Config, version int64) (string, error) {
	release, _, err := c.Github.Repositories.GetRelease(cxt, githubConfig.Owner, githubConfig.Repository, version)
	if err != nil {
		return "", err
	}
	return aws.StringValue(release.TagName), nil
}

func downloadGithubAsset(cxt context.Context, client *Client, owner string,
	repository string, id int64) ([]byte, error) {

	rawAsset, url, err := client.Github.Repositories.DownloadReleaseAsset(cxt, owner, repository, id)
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

func downloadURL(client *Client, url string) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("url is not https: %v", url)
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.HTTPClient.Do(req)
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
