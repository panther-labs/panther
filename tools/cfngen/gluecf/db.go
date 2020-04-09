package gluecf

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

// Generate CF for a gluecf database:  https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-database.html

// NOTE: the use of type interface{} allows strings and structs (e.g., cfngen.Ref{} and cfngen.Sub{} )

// Matches CF structure
type DatabaseInput struct {
	Name        interface{}
	Description string `json:",omitempty"`
}

type DatabaseProperties struct {
	CatalogID     interface{} `json:"CatalogId"` // required, string or Ref{}, need json tag to keep linter happy
	DatabaseInput DatabaseInput
}

type Database struct {
	Type       string
	DependsOn  []string `json:",omitempty"`
	Properties DatabaseProperties
}

func NewDatabase(catalogID interface{}, name, description string) (db *Database) {
	db = &Database{
		Type: "AWS::Glue::Database",
		Properties: DatabaseProperties{
			CatalogID: catalogID,
			DatabaseInput: DatabaseInput{
				Name:        name,
				Description: description,
			},
		},
	}

	return
}
