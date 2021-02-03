package clean

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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/util"
)

func Clean() error {
	log := logger.Build("[clean]")
	paths := []string{
		util.SetupDir,
		util.NpmDir,
		filepath.Join("deployments", "root_config.yml"),
		filepath.Join("internal", "core", "analysis_api", "main", "bulk_upload.zip"), // created by integration tests
		"out",
	}

	// Remove __pycache__ folders
	for _, target := range util.PyTargets {
		util.MustWalk(target, func(path string, info os.FileInfo) error {
			if strings.HasSuffix(path, "__pycache__") {
				paths = append(paths, path)
			}
			return nil
		})
	}

	for _, pkg := range paths {
		log.Info("rm -r " + pkg)
		if err := os.RemoveAll(pkg); err != nil {
			return fmt.Errorf("failed to remove %s: %v", pkg, err)
		}
	}

	return nil
}
