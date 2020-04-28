package shutil

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
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"time"
)

// ZipDirectory zips the entire directory at "root", writing a .zip file to "savefile"
//
// By default, all file headers are preserved, including modification time. However, this means
// identical files with different timestamps will create zipfiles with different hashes.
// Set preserveModTime=false to ignore modification time and generate zipfiles with consistent hashes.
func ZipDirectory(root, savefile string, preserveModTime bool) error {
	if err := os.MkdirAll(filepath.Dir(savefile), 0755); err != nil {
		return err
	}

	zipFile, err := os.Create(savefile)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		if !preserveModTime {
			header.Modified = time.Time{}
			header.ModifiedDate = 0
			header.ModifiedTime = 0
		}
		header.Name, err = filepath.Rel(root, path)
		if err != nil {
			return err
		}

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}
		_, err = io.Copy(writer, file)
		return err
	})
}
