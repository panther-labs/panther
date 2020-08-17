package mage

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
	"os"
	"strings"

	"github.com/panther-labs/panther/tools/mage/util"
)

// Clean Remove dev libraries and build/test artifacts
func Clean() {
	paths := []string{setupDirectory, "node_modules", "out", "internal/core/analysis_api/main/bulk_upload.zip"}

	// Remove __pycache__ folders
	for _, target := range pyTargets {
		util.Walk(target, func(path string, info os.FileInfo) {
			if strings.HasSuffix(path, "__pycache__") {
				paths = append(paths, path)
			}
		})
	}

	for _, pkg := range paths {
		log.Info("clean: rm -r " + pkg)
		if err := os.RemoveAll(pkg); err != nil {
			log.Fatalf("failed to remove %s: %v", pkg, err)
		}
	}
}
