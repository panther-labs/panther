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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/sh"

	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/util"
)

// Compile devtools and opstools
func Tools() error {
	var log = logger.Build("[build:tools]")

	// cross compile so tools can be copied to other machines easily
	buildEnvs := []map[string]string{
		// darwin:arm is not compatible
		{"GOOS": "darwin", "GOARCH": "amd64"},
		{"GOOS": "linux", "GOARCH": "amd64"},
		{"GOOS": "linux", "GOARCH": "arm"},
		{"GOOS": "windows", "GOARCH": "amd64"},
		{"GOOS": "windows", "GOARCH": "arm"},
	}

	var paths []string
	util.MustWalk("cmd", func(path string, info os.FileInfo) error {
		if !info.IsDir() && filepath.Base(path) == "main.go" {
			paths = append(paths, path)
		}
		return nil
	})

	for _, path := range paths {
		parts := strings.SplitN(path, `/`, 3)
		// E.g. "out/bin/cmd/devtools/" or "out/bin/cmd/opstools"
		outDir := filepath.Join("out", "bin", parts[0], parts[1])

		// used in tools to check/display which Panther version was compiled
		setVersionVar := fmt.Sprintf("-X 'main.version=%s'", util.Semver())

		log.Infof("compiling %s to %s with %d os/arch combinations",
			path, outDir, len(buildEnvs))
		for _, env := range buildEnvs {
			// E.g. "requeue-darwin-amd64"
			binaryName := filepath.Base(filepath.Dir(path)) + "-" + env["GOOS"] + "-" + env["GOARCH"]
			if env["GOOS"] == "windows" {
				binaryName += ".exe"
			}

			err := sh.RunWith(env, "go", "build",
				"-ldflags", "-s -w "+setVersionVar,
				"-o", filepath.Join(outDir, binaryName), "./"+path)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
