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
	"fmt"

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/hashicorp/go-version"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/awskms"
	githubwrapper "github.com/panther-labs/panther/pkg/github"
)

const (
	// github org and repo containing detection packs
	pantherGithubOwner = "panther-labs"
	pantherGithubRepo  = "panther-analysis"
	// signing key information
	pantherFirstSigningKeyID = "2f555f7a-636a-41ed-9a6b-c6192bf55810" //TODO: update keys
	signingAlgorithm         = kms.SigningAlgorithmSpecRsassaPkcs1V15Sha512
	// source filenames
	//pantherSourceFilename = "panther-analysis-all.zip"
	pantherTestSourceFilename = "test-panther-analysis-packs.zip"
	//pantherSignatureFilename = "panther-analysis-all.sig"
	pantherTestSignatureFilename = "test-panther-analysis-packs.sig"
	// minimum version that supports packs
	minimumVersionName = "v1.14.0"
)

var (
	pantherPackAssets = []string{
		//pantherSourceFilename,
		//pantherSignatureFilename,
		pantherTestSourceFilename,
		pantherTestSignatureFilename,
	}
	pantherGithubConfig = githubwrapper.NewConfig(
		pantherGithubOwner,
		pantherGithubRepo,
		pantherPackAssets,
	)
	signatureConfig = awskms.NewSignatureConfig(
		signingAlgorithm,
		pantherFirstSigningKeyID,
		kms.MessageTypeDigest,
	)
)

func downloadValidatePackData(config githubwrapper.Config,
	version models.Version) (map[string]*packTableItem, map[string]*tableItem, error) {

	assets, err := githubClient.DownloadGithubReleaseAssets(context.TODO(), config, version.ID)
	if err != nil {
		return nil, nil, err
	} else if len(assets) != len(pantherPackAssets) {
		return nil, nil, fmt.Errorf("missing assets in release")
	}
	//err = awskms.ValidateSignature(kmsClient, signatureConfig, assets[pantherSourceFilename], assets[pantherSignatureFilename])
	err = awskms.ValidateSignature(kmsClient, signatureConfig, assets[pantherTestSourceFilename], assets[pantherTestSignatureFilename])
	if err != nil {
		return nil, nil, err
	}
	//packs, detections, err := extractZipFileBytes(assets[pantherSourceFilename])
	packs, detections, err := extractZipFileBytes(assets[pantherTestSourceFilename])
	if err != nil {
		return nil, nil, err
	}
	return packs, detections, nil
}

func listAvailableGithubReleases(config githubwrapper.Config) ([]models.Version, error) {
	allReleases, err := githubClient.ListAvailableGithubReleases(context.TODO(), config)
	if err != nil {
		return nil, err
	}
	var availableVersions []models.Version
	// earliest version of panther managed detections that supports packs
	minimumVersion, _ := version.NewVersion(minimumVersionName)
	for _, release := range allReleases {
		version, err := version.NewVersion(*release.TagName)
		if err != nil {
			// if we can't parse the version, just throw it away
			zap.L().Warn("can't parse version", zap.String("version", *release.TagName))
			continue
		}
		if version.GreaterThanOrEqual(minimumVersion) {
			newVersion := models.Version{
				ID:   *release.ID,
				Name: *release.TagName,
			}
			availableVersions = append(availableVersions, newVersion)
		}
	}
	return availableVersions, nil
}
