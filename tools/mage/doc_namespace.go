package mage

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"fmt"
	"os"
	"path/filepath"

	"github.com/magefile/mage/mg"

	"github.com/panther-labs/panther/tools/cfndoc"
)

// targets generating documentation
type Doc mg.Namespace

const (
	inventoryDocHeader = `
<!-- This document is generated. DO NOT EDIT! -->

# <p align=center><bold>Cloud Infrastructure Inventory</bold></p>

`
)

// Cfn Cfn will generate user documentation from deployment CloudFormation
func (t Doc) Cfn() {
	logger.Infof("doc: generating operational documentation from cloudformation")
	outDir := filepath.Join("docs", "gitbook", "operations")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		logger.Fatalf("failed to create directory %s: %v", outDir, err)
	}
	inventoryFileName := filepath.Join(outDir, "inventory.md")

	inventoryFile, err := os.Create(inventoryFileName)
	if err != nil {
		logger.Fatalf("failed to create file %s: %v", inventoryFileName, err)
	}
	defer inventoryFile.Close()

	docs, err := cfndoc.ReadDirs(cfDirs...)
	if err != nil {
		logger.Fatalf("failed to generate operational documentation: %v", err)
	}

	var docsBuffer bytes.Buffer
	docsBuffer.WriteString(inventoryDocHeader)
	var lastResource string
	for _, doc := range docs {
		if doc.Resource == lastResource { // append, since these are in sorted order
			docsBuffer.WriteString(fmt.Sprintf("%s\n", doc.Documentation))
		} else {
			docsBuffer.WriteString(fmt.Sprintf("# %s\n%s\n", doc.Resource, doc.Documentation))
		}
		lastResource = doc.Resource
	}
	if _, err = inventoryFile.Write(docsBuffer.Bytes()); err != nil {
		logger.Fatalf("failed to write file %s: %v", inventoryFileName, err)
	}
}
