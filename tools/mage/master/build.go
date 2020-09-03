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

	"github.com/panther-labs/panther/tools/mage/build"
	"github.com/panther-labs/panther/tools/mage/deploy"
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
func Build() {
	build.API()
	if err := build.Cfn(); err != nil {
		log.Fatal(err)
	}
	if err := build.Lambda(); err != nil {
		log.Fatal(err)
	}

	// Use the pip libraries in the default settings file when building the layer.
	defaultConfig, err := deploy.Settings()
	if err != nil {
		log.Fatal(err)
	}

	if err = build.Layer(defaultConfig.Infra.PipLayer); err != nil {
		log.Fatal(err)
	}
}

// Package assets needed for the master template.
//
// Returns the path to the final generated template.
func Package(region, bucket, pantherVersion, imgRegistry string) string {
	pkg, err := util.SamPackage(region, "deployments/master.yml", bucket)
	if err != nil {
		log.Fatal(err)
	}

	dockerImage, err := deploy.PushWebImg(imgRegistry, pantherVersion)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("successfully published docker image %s", dockerImage)
	return pkg
}
