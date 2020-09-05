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
	"path/filepath"

	"go.uber.org/zap"

	"github.com/panther-labs/panther/tools/mage/build"
	"github.com/panther-labs/panther/tools/mage/deploy"
	"github.com/panther-labs/panther/tools/mage/gen"
	"github.com/panther-labs/panther/tools/mage/util"
)

// Get the Panther version indicated in the master template.
func GetVersion() (string, error) {
	type template struct {
		Mappings struct {
			Constants struct {
				Panther struct {
					Version string
				}
			}
		}
	}

	var cfn template
	err := util.ParseTemplate(filepath.Join("deployments", "master.yml"), &cfn)
	return cfn.Mappings.Constants.Panther.Version, err
}

// Compile Lambda source assets
func Build(log *zap.SugaredLogger) error {
	if err := gen.Gen(); err != nil {
		return err
	}
	if err := build.Lambda(); err != nil {
		return err
	}

	// Use the pip libraries in the default settings file when building the layer.
	defaultConfig, err := deploy.Settings()
	if err != nil {
		return err
	}

	return build.Layer(log, defaultConfig.Infra.PipLayer)
}

// Package assets needed for the master template.
//
// Returns the path to the final generated template.
func Package(log *zap.SugaredLogger, region, bucket, pantherVersion, imgRegistry string) (string, error) {
	pkg, err := util.SamPackage(region, "deployments/master.yml", bucket)
	if err != nil {
		return "", err
	}

	dockerImage, err := deploy.PushWebImg(imgRegistry, pantherVersion)
	if err != nil {
		return "", err
	}

	log.Infof("successfully published docker image %s", dockerImage)
	return pkg, nil
}
