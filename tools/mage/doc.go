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
	"regexp"
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
	// paths are relative to docs/gitbook/operations/runbooks.md

	inventoryDocHeader = `
<!-- This document is generated by "mage doc". DO NOT EDIT! -->

# Panther Application Run Books

Refer to the 
[Cloud Security](../cloud-security/README.md)
and
[Log Analysis](../log-analysis/README.md)
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

// Regexes for gitbooks anchor generation / verification (assumes lowercase)
var (
	// Generated links are hard to predict when numbers are mixed with single or special characters.
	// Prevent any of the following in section titles:
	//    - number + letter + number ("4X4")
	//    - letter + special + number ("AA.11")
	//    - number + special + letter ("S3.Server")
	titleEdgeCase = regexp.MustCompile(`(?:\d[a-z]\d)|(?:[a-z][^a-z0-9 -]\d)|(?:\d[^a-z0-9 -][a-z])`)

	// A number surrounded by letters - gitbooks will put dashes around it
	innerNumber = regexp.MustCompile(`[a-z]\d+[a-z]`)

	// Multiple dashes will be collapsed to a single dash
	dashGroup = regexp.MustCompile(`-{2,}`)
)

// Given markdown header text, return the anchor link gitbooks will generate for the rendered docs.
// For example, "AWS.S3" returns "aws-s3"
//
// The caller is responsible for dealing with duplicate headers in the same file - gitbooks will
// suffix these with an incremental counter: "dup", "dup-1", "dup-2", etc.
//
// Returns an error if the title is an edge case whose link we can't predict.
// Returns "undefined" for invalid headers (e.g. "***"), which mirrors the real gitbooks behavior.
//
// This was built by trial-and-error and isn't necessarily guaranteed to be correct for every edge case.
func headerAnchor(sectionTitle string) (string, error) {
	sectionTitle = strings.ToLower(sectionTitle)

	if match := titleEdgeCase.FindString(sectionTitle); match != "" {
		return "", fmt.Errorf("header \"%s\" violates pattern %s: \"%s\" - try adding spaces around numbers",
			sectionTitle, titleEdgeCase.String(), match)
	}

	// Gitbooks' number dashing rules are applied individually to each space-delimited word.
	//     "r2 d2" => "r2-d2"  (two words - number at end of each word is not surrounded with dash)
	//     "r2d2"  => "r-2-d2" (one word - inner 2 is dashed)
	var formattedWords []string
	for _, word := range strings.Split(sectionTitle, " ") {
		// Remove/replace special characters
		//     "AWS.S3ServerAccess" => "aws-s3serveraccess"
		var newWord strings.Builder
		for _, char := range word {
			switch char {
			case '&':
				newWord.WriteString("-and-")
			case '|':
				newWord.WriteString("-or-")
			case '$':
				newWord.WriteString("-usd-")
			case '<':
				newWord.WriteString("-less-than-")
			case '>':
				newWord.WriteString("-greater-than-")
			default:
				if ('a' <= char && char <= 'z') || ('0' <= char && char <= '9') {
					newWord.WriteRune(char)
				} else {
					// Replace all other special characters with a dash
					newWord.WriteRune('-')
				}
			}
		}

		// Place dashes around inner numbers
		//     "aws-s3serveraccess" => "aws-s-3-serveraccess"
		dashed := innerNumber.ReplaceAllStringFunc(newWord.String(), func(match string) string {
			// match: "s3s" or "a1111111a"
			// return (first char)-(number)-(last char)
			return match[0:1] + "-" + match[1:len(match)-1] + "-" + match[len(match)-1:]
		})
		formattedWords = append(formattedWords, dashed)
	}

	// Recombine words with a "-"
	result := strings.Join(formattedWords, "-")

	// Collapse all dash groups and remove any leading/trailing dashes
	//     "---r--2--d--2--" => "r-2-d-2"
	result = dashGroup.ReplaceAllString(result, "-")
	result = strings.Trim(result, "-")

	if result == "" {
		// If all that's left is an empty string, this header had nothing but special characters.
		// Gitbooks will label this as "undefined"
		return "undefined", nil
	}
	return result, nil
}

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
			header, err := headerAnchor(logType)
			if err != nil {
				return fmt.Errorf("%s anchor generation failed: %s", logType, err)
			}

			buf.WriteString(fmt.Sprintf("     - [%s](%s.md#%s)\n",
				strings.Split(logType, ".")[1], name, header))
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
