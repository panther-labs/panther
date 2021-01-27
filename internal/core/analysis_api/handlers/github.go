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
	"crypto/sha512"
	"encoding/base64"
	"errors"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/hashicorp/go-version"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/awsutils"
)

const (
	// github org and repo containing detection packs
	pantherGithubOwner = "lindsey-w"
	pantherGithubRepo  = "panther-analysis"
	// signing keys information
	pantherFirstSigningKeyID = "2f555f7a-636a-41ed-9a6b-c6192bf55810"
	/*pantherRootPublicKey     = "-----BEGIN PUBLIC KEY-----" +
	"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxWU9pnn5A2mdms7yyvTn" +
	"g1OYALdimf0bLuClivmLFtw4SzWOSbkN+89+4ptyLBrARmfrzsQ1Fswsgm5W+4jk" +
	"KZ7gqBY2cRtITkMIaESb2CeqaKIl2UsfjcglILFKzJVEC8qsooM4xG+/pnGxIYYj" +
	"uMTnokyg9TdQHORWyRaTFDI9qcvavJxRF8eaibk49CDY5bvUeij46mJhVjIZcyyu" +
	"d/qmDtduMfhm4UuYLD7toDmMx6YQW82/nxTo7J7OkANyYWASNFriCeCb2aIb2Gtv" +
	"7u00Fv2jdNTexQYZhJ+M4OpsG71PK6JTrSSt4nVMoiFRUb0oZhrN4odl5mEJiSDq" +
	"nHBgsJ6RiwkClN3i8F2yZ8C4tujR8BGUMoXA4z7uG7C7hDtSVcZ7eB8IY2wDBMbZ" +
	"b2cnbG1jfCnbmHaDbJfcVzDJ1RDjs89Y/MhuSz+22B5eIXdFHp4GbfUc1e/2AT4e" +
	"Ei1SaRqYj8e+6Cl0WWJjA5V2UxSJ8W9ZePCebUruAphVmf7gdSXD3Xen1uzc4Lv1" +
	"YkP0zSV5EVsV4KANVF2CzuTdHsRm05n01As7DicN1zrD01vcDdsEgmgSFELy/zvV" +
	"G4tMQJyl0P0HJMKASQ1vqMYBI8hLD1ZJCCRbRvy1U64kxeE6829MZxTeLP4g919B" +
	"w8I0Lv118RyYEBOBXLByVEcCAwEAAQ==" +
	"-----END PUBLIC KEY-----"*/
	signingAlgorithm = kms.SigningAlgorithmSpecRsassaPkcs1V15Sha512
	// source filenames
	pantherSourceFilename    = "panther-analysis-all.zip"
	pantherSignatureFilename = "panther-analysis-all.sig"
	// minimum version that supports packs
	minimumVersionName = "v1.15.0"
)

var (
	pantherPackAssets = []string{
		pantherSourceFilename,
		pantherSignatureFilename,
	}
	pantherGithubConfig = NewGithubConfig(pantherGithubOwner, pantherGithubRepo, pantherPackAssets)
)

type GithubConfig struct {
	Owner      string
	Repository string
	Assets     []string
}

func NewGithubConfig(owner string, repository string, assets []string) GithubConfig {
	return GithubConfig{
		Owner:      owner,
		Repository: repository,
		Assets:     assets,
	}
}

func downloadValidatePackData(config GithubConfig, version models.Version) (map[string]*packTableItem, map[string]*tableItem, error) {
	assets, err := githubClient.DownloadGithubReleaseAssets(config.Owner, config.Repository, version.ID, config.Assets)
	if err != nil || len(assets) != len(pantherPackAssets) {
		zap.L().Error("error downloadeing assets", zap.Error(err))
		return nil, nil, err
	}
	err = validateSignature(assets[pantherSourceFilename], assets[pantherSignatureFilename])
	if err != nil {
		return nil, nil, err
	}
	packs, detections, err := extractZipFileBytes(assets[pantherSourceFilename])
	if err != nil {
		return nil, nil, err
	}
	return packs, detections, nil
}

func listAvailableGithubReleases(config GithubConfig) ([]models.Version, error) {
	allReleases, err := githubClient.ListAvailableGithubReleases(config.Owner, config.Repository)
	if err != nil {
		return nil, err
	}
	var availableVersions []models.Version
	// earliest version of panther managed detections that supports packs
	minimumVersion, _ := version.NewVersion(minimumVersionName)
	for _, release := range allReleases {
		version, err := version.NewVersion(*release.Name)
		if err != nil {
			// if we can't parse the version, just throw it away
			zap.L().Warn("can't parse version", zap.String("version", *release.Name))
			continue
		}
		if version.GreaterThan(minimumVersion) {
			newVersion := models.Version{
				ID:   *release.ID,
				Name: *release.Name,
			}
			availableVersions = append(availableVersions, newVersion)
		}
	}
	return availableVersions, nil
}

func validateSignature(rawData []byte, signature []byte) error {
	// use hash of body in validation
	intermediateHash := sha512.Sum512(rawData)
	var computedHash []byte = intermediateHash[:]
	// The signature is base64 encoded in the file, decode it
	decodedSignature, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		zap.L().Error("error base64 decoding item", zap.Error(err))
		return err
	}
	signatureVerifyInput := &kms.VerifyInput{
		KeyId:            aws.String(pantherFirstSigningKeyID),
		Message:          computedHash,
		MessageType:      aws.String(kms.MessageTypeDigest),
		Signature:        decodedSignature,
		SigningAlgorithm: aws.String(signingAlgorithm),
	}
	result, err := kmsClient.Verify(signatureVerifyInput)
	if err != nil {
		if awsutils.IsAnyError(err, kms.ErrCodeKMSInvalidSignatureException) {
			zap.L().Error("signature verification failed", zap.Error(err))
			return err
		}
		zap.L().Warn("error validating signature", zap.Error(err))
		return err
	}
	if aws.BoolValue(result.SignatureValid) {
		zap.L().Debug("signature validation successful")
		return nil
	}
	return errors.New("error validating signature")
}
