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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/awslogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/nginxlogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/osquerylogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/osseclogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/sysloglogs"
)

// ShowSchemas returns a JSON representation each supported log type
func ShowSchemas() {
	schemas := []interface{}{
		&awslogs.ALB{},
		&awslogs.CloudTrail{},
		&awslogs.S3ServerAccess{},
		&awslogs.VPCFlow{},
		&awslogs.AuroraMySQLAudit{},
		&awslogs.GuardDuty{},
		&nginxlogs.Access{},
		&osquerylogs.Differential{},
		&osquerylogs.Batch{},
		&osquerylogs.Status{},
		&osquerylogs.Snapshot{},
		&osseclogs.EventInfo{},
		&sysloglogs.RFC3164{},
		&sysloglogs.RFC5424{},
	}
	for _, schema := range schemas {
		jsonSchema := jsonschema.Reflect(schema)
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
