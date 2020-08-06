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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type docLink struct {
	Path   string // e.g. "README.md"
	Header string // e.g. "#section-title"
}

type docSummary struct {
	// Anchor links for markdown headers.
	// For example, the "### AWS.S3" header will be listed here as "aws-s3"
	Headers map[string]struct{}

	// Links extracted from the "[text](target)" pattern
	DocLinks   []docLink
	EmailLinks []string // ["mailto:support@runpanther.io"]
	ImgLinks   []string // ["../.gitbook/assets/readme-overview.png"]
	WebLinks   []string // ["https://runpanther.io"]
}

var (
	// code blocks need to be removed before parsing headers + links
	codeBlockPattern = regexp.MustCompile("```(.|\n)*?```")

	// find section titles: "## text" at the beginning of a line
	headerPattern = regexp.MustCompile(`(?:^|\n)#+(.*)`)

	// note: we need the non-greedy variant, hence ".*?"
	linkPattern = regexp.MustCompile(`!?\[.*?\]\((.*?)\)`) // e.g. "[myfile](path/to/doc.md)"

	// Every link target must be one of the following:

	// web reference - http(s) links
	webLinkPattern = regexp.MustCompile(`^https?://[A-Za-z0-9.#?&%/:=_-]{5,}$`)

	// email link - based on the same regex we use for emails in CloudFormation parameters
	emailLinkPattern = regexp.MustCompile(`^mailto:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)

	// Asset reference - an image in the docs/gitbook/.gitbook/assets folder
	// For example, "../.gitbook/assets/log-analysis/setup-sns1.png"
	assetLinkPattern = regexp.MustCompile(`^(?:\.\./)*\.gitbook/assets/[a-z0-9/-]+\.(?:png|jpg)$`)

	// Document reference - link to another documentation page, potentially with a header.
	// For safety and consistency, we don't allow linking to directories, only specific files.
	//
	// Headers can only contain lowercase letters and dashes, but this pattern will allow a broader
	// character set so the caller can display the appropriate error message.
	//
	// Examples:
	//    - "#aws-credentials"                       (header in same file)
	//    - "../enterprise/data-analytics/README.md" (a different document)
	//    - "development.md#deploying"               (header in another file)
	//    - ""                                       (file and header are both optional in regex)
	//
	// Non-examples:
	//    - "../log-analysis"           (prevent directory links - link will fail without README)
	//    - "quick_start.md"            (use "-" instead of "_")
	docLinkPattern = regexp.MustCompile(`^([A-Za-z0-9./-]+\.md)?(#[A-Za-z0-9./-]+)?$`)
)

// Extract headers and links from a markdown document for subsequent verification.
//
// Returns an error if there are duplicate/undefined headers or links which could not be categorized.
// The caller is responsible for verifying the content of the links.
func parseDoc(path string) (*docSummary, error) {
	result := docSummary{Headers: make(map[string]struct{})}
	var errs []string

	contents := string(readFile(path))
	contents = codeBlockPattern.ReplaceAllString(contents, "")

	// Extract headers
	for _, match := range headerPattern.FindAllStringSubmatch(contents, -1) {
		// match[0] is entire "### Header Text", match[1] is just " Header Text"
		text := strings.TrimSpace(match[1])
		anchor, err := headerAnchor(text)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}

		if anchor == "#undefined" {
			errs = append(errs, fmt.Sprintf("\"%s\" results in undefined anchor - add header text", match[0]))
			continue
		}

		// Duplicate headers are allowed by gitbooks - it will add an incremental counter
		// "dup", "dup-1", "dup-2", etc.
		//
		// But we don't want to allow them because they're too fragile.
		// For example, reorganizing a file would change their ordering.
		if _, exists := result.Headers[anchor]; exists {
			// For backwards compatibility, temporarily allow duplicate headers for generated runbooks
			// TODO - fix generated runbook headers to prevent this
			if path != filepath.Join("docs", "gitbook", "operations", "runbooks.md") {
				errs = append(errs, fmt.Sprintf("duplicate header anchor #%s", anchor))
				continue
			}
		}

		// The level of header has no effect on its generated link.
		// E.g. "# AWS" and "##### AWS" will both result in "#aws" as the anchor link.
		result.Headers[anchor] = struct{}{}
	}

	// Extract links
	for _, match := range linkPattern.FindAllStringSubmatch(contents, -1) {
		// match[0] is entire "![text](link-target)", match[1] is just "link-target"
		target := match[1]

		if strings.HasPrefix(match[0], "!") {
			// Images always have ! prefix for embedding
			if assetLinkPattern.MatchString(target) {
				result.ImgLinks = append(result.ImgLinks, target)
			} else {
				errs = append(errs, fmt.Sprintf("embedded image in %s does not match expected pattern %s",
					match[0], assetLinkPattern.String()))
			}
		} else if webLinkPattern.MatchString(target) {
			result.WebLinks = append(result.WebLinks, target)
		} else if emailLinkPattern.MatchString(target) {
			result.EmailLinks = append(result.EmailLinks, target)
		} else if docMatch := docLinkPattern.FindStringSubmatch(target); docMatch != nil {
			if target == "" {
				// the doc link pattern could match an empty string
				errs = append(errs, fmt.Sprintf("%s has empty link target", match[0]))
			} else {
				result.DocLinks = append(result.DocLinks, docLink{Path: docMatch[1], Header: docMatch[2]})
			}
		} else {
			// This link couldn't be classified - try to offer a helpful error message for common mistakes
			if assetLinkPattern.MatchString(target) {
				errs = append(errs, fmt.Sprintf("%s looks like an image, but is not prefixed with !", match[0]))
				continue
			}

			if strings.Contains(target, ".com") || strings.Contains(target, ".io") {
				errs = append(errs, fmt.Sprintf("%s is invalid - be sure web links are "+
					"prefixed with \"http(s)://\" and email links are prefixed with \"mailto:\"", match[0]))
				continue
			}

			if info, err := os.Stat(filepath.Join(filepath.Dir(path), target)); err == nil && info.IsDir() {
				// Linking to a directory without a README will result in a broken link.
				// For simplicity, then, we disallow all directory links.
				errs = append(errs, fmt.Sprintf(
					"%s is invalid - directory links are not allowed, link to a specific .md file", match[0]))
				continue
			}

			errs = append(errs, fmt.Sprintf(
				"%s is invalid - non-image links must match one of these patterns:\n%s\n%s\n%s",
				match[0], webLinkPattern.String(), emailLinkPattern.String(), docLinkPattern.String()))
		}
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("%s: %d parsing errors:\n - %s", path, len(errs), strings.Join(errs, "\n - "))
	}
	return &result, nil
}
