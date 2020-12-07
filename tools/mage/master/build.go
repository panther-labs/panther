package master

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
	"bytes"
	"path/filepath"

	"github.com/aws/aws-sdk-go/service/ecr"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/tools/mage/build"
	"github.com/panther-labs/panther/tools/mage/deploy"
	"github.com/panther-labs/panther/tools/mage/gen"
	"github.com/panther-labs/panther/tools/mage/srcfmt"
	"github.com/panther-labs/panther/tools/mage/util"
)

var masterTemplate = filepath.Join("deployments", "master.yml")

// Build lambda functions, python layer, and docker image.
//
// Returns docker image ID.
func buildAssets(log *zap.SugaredLogger) (string, error) {
	if err := gen.Gen(); err != nil {
		return "", err
	}
	if err := srcfmt.Fmt(); err != nil {
		return "", err
	}

	if err := build.Lambda(); err != nil {
		return "", err
	}

	// Use the pip libraries in the default settings file when building the layer.
	defaultConfig, err := deploy.Settings()
	if err != nil {
		return "", err
	}
	if err := build.Layer(log, defaultConfig.Infra.PipLayer); err != nil {
		return "", err
	}

	return deploy.DockerBuild()
}

// Package assets needed for the master template.
//
// Returns the path to the final generated template.
func pkgAssets(log *zap.SugaredLogger, ecrClient *ecr.ECR, region, bucket, imgRegistry, dockerImageID string) (string, error) {
	pkg, err := util.SamPackage(region, masterTemplate, bucket)
	if err != nil {
		return "", err
	}

	// Embed the version directly into the final template - we don't want this to be a configurable parameter.
	//
	// There is roughly a 1.4% chance that the commit tag looks like scientific notation, e.g. "715623e8"
	// Even if the value is surrounded by quotes in the original template, `sam package` will remove them!
	// Then CloudFormation will standardize the scientific notation, e.g. "7.15623E13"
	//
	// So, until we implement our own packaging, we have to do the version embedding *after* sam package.
	template := util.MustReadFile(pkg)
	template = bytes.Replace(template, []byte("${{PANTHER_COMMIT}}"), []byte(`'`+util.CommitSha()+`'`), 1)
	template = bytes.Replace(template, []byte("${{PANTHER_VERSION}}"), []byte(`'`+util.Semver()+`'`), 1)
	util.MustWriteFile(pkg, template)

	dockerImage, err := deploy.DockerPush(ecrClient, imgRegistry, dockerImageID, util.Semver())
	if err != nil {
		return "", err
	}

	log.Infof("successfully published docker image %s", dockerImage)
	return pkg, nil
}
