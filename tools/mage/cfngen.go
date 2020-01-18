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
	"os"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/tools/cfngen/gluecf"
)

// Generate Glue tables for log processor output as CloudFormation
func generateGlueTables() (err error) {
	outDir := "out/deployments/log_analysis"
	err = os.MkdirAll(outDir, 0755)
	if err != nil {
		return
	}
	glueCfFileName := outDir + "/gluetables.json"

	glueCfFile, err := os.Create(glueCfFileName)
	if err != nil {
		return
	}
	defer func() {
		glueCfFile.Close()
	}()

	cf, err := gluecf.GenerateCloudFormation(registry.AvailableTables())
	if err != nil {
		return
	}
	_, err = glueCfFile.Write(cf)
	return
}
