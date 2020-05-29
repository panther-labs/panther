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
	"bytes"
	"fmt"
	"html"
	"path/filepath"
	"sort"
	"strings"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/tools/cfndoc"
)

// Auto-generate specific sections of documentation
func Doc() {
	if err := doc(); err != nil {
		logger.Fatal(err)
	}
}

func doc() error {
	if err := opDocs(); err != nil {
		return err
	}
	return logDocs()
}

const (
	inventoryDocHeader = `
<!-- This document is generated by "mage doc:cfn". DO NOT EDIT! -->

# Panther Application Run Books

Refer to the 
[Cloud Security](https://docs.runpanther.io/policies/scanning#how-it-works)
and
[Log Analysis](https://docs.runpanther.io/log-analysis/log-processing#how-it-works)
architecture diagrams for context.

Resource names below refer to resources in the Cloud Formation templates in Panther.

Each resource describes its function and failure impacts.

`
)

// generate operational documentation from deployment CloudFormation
func opDocs() error {
	logger.Infof("doc: generating operational documentation from cloudformation")
	docs, err := cfndoc.ReadCfn(cfnFiles()...)
	if err != nil {
		return fmt.Errorf("failed to generate operational documentation: %v", err)
	}

	var docsBuffer bytes.Buffer
	docsBuffer.WriteString(inventoryDocHeader)
	for _, doc := range docs {
		docsBuffer.WriteString(fmt.Sprintf("## %s\n%s\n\n", doc.Resource, doc.Documentation))
	}

	return writeFile(filepath.Join("docs", "gitbook", "operations", "runbooks.md"), docsBuffer.Bytes())
}

const (
	parserReadmeHeader = `
<!-- This document is generated by "mage doc:logs". DO NOT EDIT! -->
`
)

func logDocs() error {
	logger.Infof("doc: generating documentation on supported logs")
	outDir := filepath.Join("docs", "gitbook", "log-analysis", "log-processing", "supported-logs")

	// group the data by category
	tables := registry.AvailableTables()
	logCategories := make(map[string][]string) // category -> logTypes
	for _, table := range tables {
		logType := table.LogType()
		categoryType := strings.Split(logType, ".")
		if len(categoryType) != 2 {
			return fmt.Errorf("unexpected logType format: %s", logType)
		}
		logCategories[categoryType[0]] = append(logCategories[categoryType[0]], logType)
	}
	var sortedCategories []string
	for category := range logCategories {
		sortedCategories = append(sortedCategories, category)
		sort.Strings(logCategories[category])
	}
	sort.Strings(sortedCategories)

	docCategory := func(category string) error {
		var docsBuffer bytes.Buffer
		logTypes := logCategories[category]
		docsBuffer.WriteString(parserReadmeHeader)
		docsBuffer.WriteString(fmt.Sprintf("# %s\n%sRequired fields are in <b>bold</b>.%s\n",
			category,
			`{% hint style="info" %}`,
			`{% endhint %}`))

		// use html table to get needed control
		for _, logType := range logTypes {
			table := registry.AvailableParsers().LookupParser(logType).GlueTableMetadata

			description := html.EscapeString(table.Description())

			docsBuffer.WriteString(fmt.Sprintf("##%s\n%s\n", logType, description))

			// add schema as html table since markdown won't let you embed tables
			docsBuffer.WriteString(`<table>` + "\n")
			docsBuffer.WriteString("<tr><th align=center>Column</th><th align=center>Type</th><th align=center>Description</th></tr>\n") // nolint

			columns := awsglue.InferJSONColumns(table.EventStruct(), awsglue.GlueMappings...) // get the Glue schema
			for _, column := range columns {
				colName := column.Name
				if column.Required {
					colName = "<b>" + colName + "</b>" // required elements are bold
				}
				docsBuffer.WriteString(fmt.Sprintf("<tr><td valign=top>%s</td><td>%s</td><td valign=top>%s</td></tr>\n",
					formatColumnName(colName),
					formatType(logType, column),
					html.EscapeString(column.Comment)))
			}

			docsBuffer.WriteString("</table>\n\n")
		}

		return writeFile(filepath.Join(outDir, category+".md"), docsBuffer.Bytes())
	}

	// one file per category
	for _, category := range sortedCategories {
		if err := docCategory(category); err != nil {
			return err
		}
	}

	return nil
}

func formatColumnName(name string) string {
	return "<code>" + name + "</code>"
}

func formatType(logType string, col awsglue.Column) string {
	return "<code>" + prettyPrintType(logType, col.Name, col.Type, "") + "</code>"
}

const (
	prettyPrintPrefix = "<br>"
	prettyPrintIndent = "&nbsp;&nbsp;"
)

func prettyPrintType(logType, colName, colType, indent string) string {
	complexTypes := []string{"array", "struct", "map"}
	for _, ct := range complexTypes {
		if strings.HasPrefix(colType, ct) {
			return prettyPrintComplexType(logType, colName, ct, colType, indent)
		}
	}

	// if NOT a complex type we just use the Glue type
	return colType
}

// complex hive types are ugly
func prettyPrintComplexType(logType, colName, complexType, colType, indent string) (pretty string) {
	switch complexType {
	case "array":
		return prettyPrintArrayType(logType, colName, colType, indent)
	case "map":
		return prettyPrintMapType(logType, colName, colType, indent)
	case "struct":
		return prettyPrintStructType(logType, colName, colType, indent)
	default:
		panic("unknown complex type: " + complexType + " for " + colName + " in " + logType)
	}
}

func prettyPrintArrayType(logType, colName, colType, indent string) string {
	fields := getTypeFields("array", colType)
	if len(fields) != 1 {
		panic("could not parse array type `" + colType + "` for " + colName + " in " + logType)
	}
	return "[" + prettyPrintType(logType, colName, fields[0], indent) + "]"
}

func prettyPrintMapType(logType, colName, colType, indent string) string {
	fields := getTypeFields("map", colType)
	if len(fields) != 2 {
		panic("could not parse map type `" + colType + "` for " + colName + " in " + logType)
	}
	keyType := fields[0]
	valType := fields[1]
	indent += prettyPrintIndent
	return "{" + prettyPrintPrefix + indent + prettyPrintType(logType, colName, keyType, indent) + ":" +
		prettyPrintType(logType, colName, valType, indent) + prettyPrintPrefix + "}"
}

func prettyPrintStructType(logType, colName, colType, indent string) string {
	fields := getTypeFields("struct", colType)
	if len(fields) == 0 {
		panic("could not parse struct type `" + colType + "` for " + colName + " in " + logType)
	}
	indent += prettyPrintIndent
	var fieldTypes []string
	for _, field := range fields {
		splitIndex := strings.Index(field, ":") // name:type (can't use Split() cuz type can have ':'
		if splitIndex == -1 {
			panic("could not parse struct field `" + field + "` of `" + colType + "` for " + colName + " in " + logType)
		}
		name := `"` + field[0:splitIndex] + `"` // make it look like JSON by quoting
		structFieldType := field[splitIndex+1:]
		fieldTypes = append(fieldTypes, prettyPrintPrefix+indent+name+":"+
			prettyPrintType(logType, colName, structFieldType, indent))
	}
	return "{" + strings.Join(fieldTypes, ",") + prettyPrintPrefix + "}"
}

func getTypeFields(complexType, colType string) (subFields []string) {
	// strip off complexType + '<' in front and '>' on end
	fields := colType[len(complexType)+1 : len(colType)-1]
	// split fields into subFields around top level commas in type definition
	startSubfieldIndex := 0
	insideBracketCount := 0 // when non-zero we are inside a complex type
	var index int
	for index = range fields {
		if fields[index] == ',' && insideBracketCount == 0 {
			subFields = append(subFields, fields[startSubfieldIndex:index])
			startSubfieldIndex = index + 1 // next
		}
		// track context
		if fields[index] == '<' {
			insideBracketCount++
		} else if fields[index] == '>' {
			insideBracketCount--
		}
	}
	if len(fields[startSubfieldIndex:]) > 0 { // the rest
		subFields = append(subFields, fields[startSubfieldIndex:])
	}
	return subFields
}
