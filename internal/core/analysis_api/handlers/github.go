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
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/go-version"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	githubwrapper "github.com/panther-labs/panther/pkg/github"
)

const (
	// github org and repo containing detection packs
	pantherGithubOwner = "lindsey-w"
	pantherGithubRepo  = "panther-analysis"
	// signing key information
	pantherPublicKey = "-----BEGIN PUBLIC KEY-----\n" + // TODO: update keys
		"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtfz6a2sbfwNk+4NG8RTr\n" +
		"Gwict6eO7Nd7r2snHyeqElt0xv0LVqG0ynqMHGxvhXKI6wk6qv8rpFNlDU0Ha7/v\n" +
		"G9QHrkPuXvy5XU6g1jR6DCqo2Fqed3QBdwTg+JVz6ojMorwRut1DbFFh+MNuCKF2\n" +
		"k5vbsRdNnz/+Eh+JAgkfqxLxG64hjzzjqVmfnLTgy1sZGR5UGBytBpGRZys4sJ2v\n" +
		"m9/JTc3fU0lhp5xmWfJcgbADAPQuYI2TD9aNpZlD5y7XST3fY6NV+GI/dwe9G/ln\n" +
		"s8Rz+s9vKHXk6U6S/OO9aW3Ct+Erh/MDhlnqaoegWA7YiL3YR3X4bo/TtmD4miNF\n" +
		"QPxfbsw8UTi7CA0it/Dvpzw3C00+klnmOiMr76GqXKda3U5QrEpnYXEgzUifnUM6\n" +
		"COGWY+LJwbxiFfYPg+D1MD8AggRIH+LCXOF3PocnK2ra1xnGEcuArQ2qFJEX3szL\n" +
		"Z2HT9hKpgkX/9UvSwkfCdY8n3MRDn3o3HDJ43whpJblNMEIePhOZAyqd6XzVqwPr\n" +
		"9f33GImZOznkcxB4jJEIRdDnDmDI+jpOZfqZpmudS8zhHERP2Nm1DZ4ar/nVCRps\n" +
		"k1jSCMM9mPFWxFDJbdGjDzTtjyqHxBkR3ovJcP///pYhndZw6kIIprALfr1658Fa\n" +
		"ex+7VGQN6Ptf1P9m6OIACLcCAwEAAQ==\n" +
		"-----END PUBLIC KEY-----"
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
)

func downloadValidatePackData(config githubwrapper.Config,
	version int64) (map[string]*packTableItem, map[string]*tableItem, error) {

	assets, err := githubClient.DownloadGithubReleaseAssets(context.TODO(), config, version)
	if err != nil {
		return nil, nil, err
	} else if len(assets) != len(pantherPackAssets) {
		return nil, nil, fmt.Errorf("missing assets in release")
	}
	//err = validateSignature([]byte(pantherPublicKey), assets[pantherSourceFilename], assets[pantherSignatureFilename])
	err = validateSignature([]byte(pantherPublicKey), assets[pantherTestSourceFilename], assets[pantherTestSignatureFilename])
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
}
