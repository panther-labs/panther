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
	"math"
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
<!-- This document is generated by "mage doc". DO NOT EDIT! -->

# Panther Application Run Books

Refer to the 
[Cloud Security](https://docs.runpanther.io/cloud-security/cloud-security)
and
[Log Analysis](https://docs.runpanther.io/log-analysis/log-analysis)
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
<!-- This document is generated by "mage doc". DO NOT EDIT! -->
`
)

type supportedLogs struct {
	Categories map[string]*logCategory
	TotalTypes int
}

// Generate entire "supported-logs" documentation directory
func (logs *supportedLogs) generateDocumentation() error {
	outDir := filepath.Join("docs", "gitbook", "log-analysis", "log-processing", "supported-logs")
	categoryNames := make([]string, 0, len(logs.Categories))

	// Write one file for each category.
	for name, category := range logs.Categories {
		categoryNames = append(categoryNames, name)
		if err := category.generateDocFile(outDir); err != nil {
			return err
		}
	}

	// Write the summary README.md with links to every log type.
	var buf bytes.Buffer
	buf.WriteString(parserReadmeHeader)
	buf.WriteString("\n# Supported Logs\n")
	buf.WriteString(fmt.Sprintf(
		"Panther currently supports %d security log types across %d different categories:\n\n",
		logs.TotalTypes, len(logs.Categories)))

	// Bulleted list of links:
	//
	// - [AWS](AWS.md)
	//     - [ALB](AWS.md#aws-alb)
	//     - [AuroraMySQLAudit](AWS.md#aws-auroramysqlaudit)

	sort.Strings(categoryNames)
	for _, name := range categoryNames {
		buf.WriteString(fmt.Sprintf(" - [%s](%s.md)\n", name, name))

		// log types are already sorted
		for _, logType := range logs.Categories[name].LogTypes {
			buf.WriteString(fmt.Sprintf("     - [%s](%s.md#%s)\n",
				strings.Split(logType, ".")[1], name,
				// TODO - numbers in headers get real weird
				// https://docs.runpanther.io/v/austin-ci-docs/log-analysis/rules
				//
				// Rules seem to be:
				//    - always lowercase
				//    - replace spaces and special characters with -
				//        - except at beginning/end - ignore these
				//    - numbers are injected with dashes on either side, except:
				//        - beginning/end of string
				//    - duplicate headers get an incrementing "-1" suffix, regardless of size
				//
				// "S3.ServerAccess" => "s-3-serveraccess"
				// "A1B2C3D4" => "a-1-b2c-3-d4"
				// "12345" => "12345"
				// "A-1-B-2-C-3" => "a-1-b-2-c-3"
				// "ABC 123 DEF" => "abc-123-def"
				// "A1B2C3D4E5F6G7H8I9J0" => "a-1-b2c-3-d4e-5-f6g-7-h8i-9-j0"
				// "3S" => "3s"
				// "S3" => "s3"
				// "3" => "3"
				// "13" => "13"
				// "33" => "33"
				// "A0A B1B C2C D3D E0E" => "a-0-a-b-1-b-c-2-c-d-3-d-e-0-e"
				// "F10FG11GH12HI13I" => "f-10-fg-11-gh-12-hi-13-i"
				// "rules2me" => "rules-2-me" (tested with other digits as well)
				// "B1BA2A" => "b-1-ba-2-a"
				// "A2AC3C" => "a-2-ac-3-c"
				// "alpha1beta2charlie3delta" => "alpha-1-beta-2-charlie-3-delta"
				//
				// "A-1-B-2-C-3" => "a-1-b-2-c-3"
				// "A1B2C3" => "a-1-b2c3"
				// "A1B2C3D4" => "a-1-b2c-3-d4"
				// "-A-1-b-2-c-3-d-4-" => "a-1-b-2-c-3-d-4"
				// "A--1--B--2--C--3--D--4" => "a-1-b-2-c-3-d-4" (with "-1" duplicate suffix)
				// "A - 1 - B - 2 - C - 3 - D - 4" => "a-1-b-2-c-3-d-4" (with "-2" duplicate suffix)
				// "A..1..B..2..C..3..D..4" => "a-1-b-2-c-3-d-4"
				// "A.1.B.2.C.3.D.4" => "a-1-b-2-c-3-d-4"
				//
				// (duplicate suffixes omitted in this section)
				// dot is always replaced by a dash, but a dot and a space affect subsequent numeric grouping differently
				// space - run algorithm on two groups separately
				//
				// "A1B2C3D4" => "a-1-b2c-3-d4"
				// "A.1B2C3D4" => "a-1-b2c-3-d4"
				// "A 1B2C3D4" -> "a-1b-2-c3d4"
				// "A1.B2C3D4" => "a-1-b2c-3-d4"
				// "A1 B2C3D4" => "a1-b-2-c3d4"
				// "A1B.2C3D4" => "a-1-b-2-c3d4"
				// "A1B 2C3D4" => "a-1-b-2c-3-d4"
				// "A1B2.C3D4" => "a-1-b2-c-3-d4"
				// "A1B2 C3D4" => "a-1-b2-c-3-d4"
				// "A1B2C.3D4" => "a-1-b2c-3-d4"
				// "A1B2C 3D4" => "a-1-b2c-3d4"
				// "A1B2C3.D4" => "a-1-b2c-3-d4"
				// "A1B2C3 D4" => "a-1-b2c3-d4"
				// "A1B2C3D.4" => "a-1-b2c-3-d-4"
				// "A1B2C3D 4" => "a-1-b2c-3-d-4"
				//
				// "3.5" => "3-5"
				// "A1" => "a1"
				// "A1B" => "a-1-b"
				// "\"A1B\"" => "a-1-b-1" (considered duplicate of previous)
				// "A1B2" => "a-1-b2"
				// "A1B2C" => "a-1-b2c"
				// "A1B2C3" => "a-1-b2c3"
				// "A1B2C3D" => "a-1-b2c-3-d"
				// "A1B2C3D4" => "a-1-b2c-3-d4"
				// "A0B0C0D0" => "a-0-b0c-0-d0"
				// "0A0B0C0D" => "0a-0-b0c-0-d"
				// "0AAA0AAA0" => "0aaa-0-aaa0"
				// "B2C" => "b-2-c"
				// "B2C3 => "b-2-c3"
				//
				// "." => "undefined"
				// ".." => "undefined-1" (duplicate of last one)
				// "%..%" => "undefined-2"
				// "!@#$%^&A()()()=-" => "usd-and-a"
				// "0A0A0A0A0A0" => "0a-0-a0a-0-a0a0"
				// "0AA0AA0AA0AA0" => "0aa-0-aa-0-aa-0-aa0"
				// "0AAA0AAA0AAA0AAA0" => "0aaa-0-aaa-0-aaa-0-aaa0"
				//
				// "-" => "undefined"
				// "--" => "undefined-1"
				// "-A-" => "undefined"
				// "-:A:{}[]|\/-<>?" => "a-or-less-than-greater-than"
				// "_a" => "_a"
				// "A0A0A0A" => "a-0-a0a-0-a"
				// "A00A00A00A" => "a-00-a00a-00-a"
				// "000A000A000A000A000A000" => "000a-000-a000a-000-a000a000"
				//
				// "000AA000AA000AA000AA000AA000" => "000aa-000-aa-000-aa-000-aa-000-aa000"
				// "000 A 000 A 000 A 000 A 000 A 000" => "000-a-000-a-000-a-000-a-000-a-000"
				// "S3......Server" => "s-3-server"
				// "S3.Server" => "s-3-server-1"
				// "S3 Server" => "s3-server"
				// "S3Server" => "s-3-server-2"
				// "S3S" => "s-3-s"
				strings.ToLower(strings.ReplaceAll(logType, ".", "-"))))
		}
	}

	buf.WriteString("\nIf you don't see what you need listed here, you can [write your own parser](../writing-parsers.md)" +
		" or [upgrade to Panther Enterprise](https://runpanther.io/pricing).")

	return writeFile(filepath.Join(outDir, "README.md"), buf.Bytes())
}

type logCategory struct {
	Name     string
	LogTypes []string
}

// Generate a single documentation file for a log category, e.g. "AWS.md"
func (category *logCategory) generateDocFile(outDir string) error {
	sort.Strings(category.LogTypes)

	var docsBuffer bytes.Buffer
	docsBuffer.WriteString(parserReadmeHeader)
	docsBuffer.WriteString(fmt.Sprintf("# %s\n%sRequired fields are in <b>bold</b>.%s\n",
		category.Name,
		`{% hint style="info" %}`,
		`{% endhint %}`))

	// use html table to get needed control
	for _, logType := range category.LogTypes {
		entry := registry.Lookup(logType)
		table := entry.GlueTableMeta()
		entryDesc := entry.Describe()
		desc := entryDesc.Description
		if entryDesc.ReferenceURL != "-" {
			desc += "\n" + "Reference: " + entryDesc.ReferenceURL + "\n"
		}

		description := html.EscapeString(desc)

		docsBuffer.WriteString(fmt.Sprintf("##%s\n%s\n", logType, description))

		// add schema as html table since markdown won't let you embed tables
		docsBuffer.WriteString(`<table>` + "\n")
		docsBuffer.WriteString("<tr><th align=center>Column</th><th align=center>Type</th><th align=center>Description</th></tr>\n") // nolint

		columns, _ := awsglue.InferJSONColumns(table.EventStruct(), awsglue.GlueMappings...) // get the Glue schema
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

	path := filepath.Join(outDir, category.Name+".md")
	logger.Debugf("writing log category documentation: %s", path)
	return writeFile(path, docsBuffer.Bytes())
}

func logDocs() error {
	logger.Infof("doc: generating documentation on supported logs")

	// allow large comment descriptions in the docs (by default they are clipped)
	awsglue.MaxCommentLength = math.MaxInt32
	defer func() {
		awsglue.MaxCommentLength = awsglue.DefaultMaxCommentLength
	}()

	logs, err := findSupportedLogs()
	if err != nil {
		return err
	}

	return logs.generateDocumentation()
}

// Group log registry by category
func findSupportedLogs() (*supportedLogs, error) {
	result := supportedLogs{Categories: make(map[string]*logCategory)}

	tables := registry.AvailableTables()
	for _, table := range tables {
		logType := table.LogType()
		categoryType := strings.Split(logType, ".")
		if len(categoryType) != 2 {
			return nil, fmt.Errorf("unexpected logType format: %s", logType)
		}
		name := categoryType[0]

		category, exists := result.Categories[name]
		if !exists {
			category = &logCategory{Name: name}
			result.Categories[name] = category
		}
		category.LogTypes = append(category.LogTypes, logType)
		result.TotalTypes++
	}

	return &result, nil
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
