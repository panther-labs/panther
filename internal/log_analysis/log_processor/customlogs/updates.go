package customlogs

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
	"strings"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
)

func CheckSchemaChange(d *logschema.Change) error {
	switch d.Type {
	case logschema.DeleteField:
		// Note that field renames appear in a change log as a pair of DeleteField, AddField
		target, path := splitPath(d.Path)
		return errors.Errorf("cannot delete field %q at %q", target, path)
	case logschema.UpdateValue:
		from, to := d.From.(*logschema.ValueSchema), d.To.(*logschema.ValueSchema)
		// TODO: check type of change to see if it is backwards compatible
		// Currently we do not allow *any* type changes until we verify 'transparent' migrations across Glue/Athena/Parquet/Snowflake
		if from.Type != to.Type {
			target, path := splitPath(d.Path)
			// Detect array element
			if target == "*" {
				target, path := splitPath(d.Path[:len(d.Path)-1])
				return errors.Errorf("cannot change element type from %q to %q on field %q at %q", from.Type, to.Type, target, path)
			}
			return errors.Errorf("cannot change value type from %q to %q on field %q at %q", from.Type, to.Type, target, path)
		}
		return nil
	default:
		return nil
	}
}

func splitPath(path []string) (string, string) {
	if last := len(path) - 1; 0 <= last && last < len(path) {
		return path[last], strings.Join(path[:last], ".")
	}
	return "", ""
}
