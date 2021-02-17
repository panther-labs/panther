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

	"github.com/aws/aws-sdk-go/aws"
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
	pantherSigningKeyID     = "arn:aws:kms:us-west-2:349240696275:key/57e3be93-237b-4de2-886f-d1e1aaa38b09"
	pantherSigningAlgorithm = kms.SigningAlgorithmSpecRsassaPkcs1V15Sha512
	// source filenames
	pantherSourceFilename    = "panther-analysis-all.zip"
	pantherSignatureFilename = "panther-analysis-all.sig"
	// minimum version that supports packs
	minimumVersionName = "v1.16.0"
)

var (
	pantherPackAssets = []string{
		pantherSourceFilename,
		pantherSignatureFilename,
	}
	pantherGithubConfig = githubwrapper.NewConfig(
		pantherGithubOwner,
		pantherGithubRepo,
		pantherPackAssets,
	)
	signatureConfig = awskms.NewSignatureConfig(
		pantherSigningAlgorithm,
		pantherSigningKeyID,
		kms.MessageTypeDigest,
	)
)

func downloadValidatePackData(config githubwrapper.Config,
	version int64) (map[string]*packTableItem, map[string]*tableItem, error) {

	assets, err := githubClient.DownloadGithubReleaseAssets(context.TODO(), config, version)
	if err != nil {
		return nil, nil, err
	} else if len(assets) != len(pantherPackAssets) {
		return nil, nil, fmt.Errorf("missing assets in release")
	}
	err = awskms.ValidateSignature(kmsClient, signatureConfig, assets[pantherSourceFilename], assets[pantherSignatureFilename])
	if err != nil {
		return nil, nil, err
	}
	packs, detections, err := extractZipFileBytes(assets[pantherSourceFilename])
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
		if aws.BoolValue(release.Draft) {
			// we don't care about draft releases
			continue
		}
		version, err := version.NewVersion(aws.StringValue(release.TagName))
		if err != nil {
			// if we can't parse the version, just throw it away
			zap.L().Warn("can't parse version", zap.String("version", aws.StringValue(release.TagName)))
			continue
		}
		if version.GreaterThanOrEqual(minimumVersion) {
			newVersion := models.Version{
				ID:     *release.ID,
				SemVer: *release.TagName,
			}
			availableVersions = append(availableVersions, newVersion)
		}
	}
	return availableVersions, nil
}

func getReleaseName(config githubwrapper.Config, version int64) (string, error) {
	// validate the user supplied version information matches up (name <->id)
	return githubClient.GetReleaseTagName(context.TODO(), config, version)
}

/* This can be used for general sign/verify if we want to use pub keys in config
// validateSignature can validate data that is signed by RSA key
func validateSignature(publicKey []byte, rawData []byte, signature []byte) error {
	// use hash of body in validation
	intermediateHash := sha512.Sum512(rawData)
	var computedHash []byte = intermediateHash[:]
	// The signature is base64 encoded in the file, decode it
	decodedSignature, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		zap.L().Error("error base64 decoding item", zap.Error(err))
		return err
	}
	// load in the pubkey
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return fmt.Errorf("error decoding public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	// TODO: only support rsa keys?
	pubKey := key.(*rsa.PublicKey)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA512, computedHash[:], decodedSignature)
	return err
} */
