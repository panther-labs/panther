package build

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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/magefile/mage/sh"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/shutil"
	"github.com/panther-labs/panther/tools/mage/util"
)

const (
	layerSourceDir = "out/pip/analysis/python"
	layerSigfile   = "out/layer-signature.txt" // hash of pip libraries
	layerZipfile   = "out/layer.zip"
)

// Build standard Python analysis layer in out/layer.zip if that file doesn't already exist.
func Layer(log *zap.SugaredLogger, libs []string) error {
	// If the layer checksum matches, we don't need to rebuild the layer
	sort.Strings(libs)
	hash := sha256.New()
	for _, lib := range libs {
		if _, err := hash.Write([]byte(lib)); err != nil {
			return err
		}
	}
	checksum := hex.EncodeToString(hash.Sum(nil))

	if sig, err := ioutil.ReadFile(layerSigfile); err == nil {
		if _, err = os.Stat(layerZipfile); err == nil && string(sig) == checksum {
			log.Debugf("%s already exists with matching signature, not rebuilding layer", layerZipfile)
			return nil
		}
	}

	log.Info("downloading python libraries " + strings.Join(libs, ","))
	if err := os.RemoveAll(layerSourceDir); err != nil {
		return fmt.Errorf("failed to remove layer directory %s: %v", layerSourceDir, err)
	}
	if err := os.MkdirAll(layerSourceDir, 0700); err != nil {
		return fmt.Errorf("failed to create layer directory %s: %v", layerSourceDir, err)
	}
	args := append([]string{"install", "-t", layerSourceDir}, libs...)
	if err := sh.Run("pip3", args...); err != nil {
		return fmt.Errorf("failed to download pip libraries: %v", err)
	}

	// The package structure needs to be:
	//
	// layer.zip
	// │ python/policyuniverse/
	// └ python/policyuniverse-VERSION.dist-info/
	//
	// https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html#configuration-layers-path
	if err := shutil.ZipDirectory(filepath.Dir(layerSourceDir), layerZipfile, false); err != nil {
		return fmt.Errorf("failed to zip %s into %s: %v", layerSourceDir, layerZipfile, err)
	}

	util.MustWriteFile(layerSigfile, []byte(checksum))
	return nil
}
