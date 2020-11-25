package awsglue

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

// Infers Glue table column types from Go types, recursively descends types

import (
	"github.com/panther-labs/panther/internal/log_analysis/awsglue/glueschema"
)

type Column = glueschema.Column

var (
	// RuleMatchColumns are columns added by the rules engine
	RuleMatchColumns = []Column{
		{
			Name:    "p_rule_id",
			Type:    glueschema.TypeString,
			Comment: "Rule id",
		},
		{
			Name:    "p_alert_id",
			Type:    glueschema.TypeString,
			Comment: "Alert id",
		},
		{
			Name:    "p_alert_context",
			Type:    glueschema.TypeString,
			Comment: "Additional alert context",
		},
		{
			Name:    "p_alert_creation_time",
			Type:    glueschema.TypeTimestamp,
			Comment: "The time the alert was initially created (first match)",
		},
		{
			Name:    "p_alert_update_time",
			Type:    glueschema.TypeTimestamp,
			Comment: "The time the alert last updated (last match)",
		},
		{
			Name:    "p_rule_tags",
			Type:    glueschema.ArrayOf(glueschema.TypeString),
			Comment: "The tags of the rule that generated this alert",
		},
		{
			Name:    "p_rule_reports",
			Type:    glueschema.MapOf(glueschema.TypeString, glueschema.ArrayOf(glueschema.TypeString)),
			Comment: "The reporting tags of the rule that generated this alert",
		},
	}

	// RuleErrorColumns are columns added by the rules engine
	RuleErrorColumns = append(
		RuleMatchColumns,
		Column{
			Name:    "p_rule_error",
			Type:    glueschema.TypeString,
			Comment: "The rule error",
		},
	)
)
