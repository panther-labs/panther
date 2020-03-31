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
	"encoding/json"
	"fmt"

	"github.com/alecthomas/jsonschema"
	"github.com/magefile/mage/mg"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
)

type Show mg.Namespace

// Schemas Prints to stdout a JSON representation each supported log type
func (b Show) Schemas() {
	for _, parser := range registry.AvailableParsers() {
		jsonSchema := jsonschema.Reflect(parser.GlueTableMetadata.EventStruct())
		for name, schemaType := range jsonSchema.Definitions {
			fmt.Println(name)
			props, err := json.MarshalIndent(schemaType.Properties, "", "    ")
			if err != nil {
				logger.Error(err)
			}
			fmt.Printf("%s\n", string(props))
		}
	}
}
