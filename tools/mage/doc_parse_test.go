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
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDocParseBasic(t *testing.T) {
	summary, err := parseDoc(filepath.Join("testdata", "docs", "quick-start.md"))
	require.NoError(t, err)

	expected := &docSummary{
		Headers: map[string]struct{}{
			"test-only-quick-start": {},
		},
		WebLinks: []string{"https://docs.runpanther.io/quick-start"},
	}

	assert.Equal(t, expected, summary)
}

func TestDocParseFull(t *testing.T) {
	summary, err := parseDoc(filepath.Join("testdata", "docs", "development.md"))
	require.NoError(t, err)

	expected := &docSummary{
		Headers: map[string]struct{}{
			"test-only-development": {},
			"panther-logo":          {},
			"environment":           {},
			"development-image":     {},
			"local-dependencies":    {},
			"repo-layout":           {},
			"deploying":             {},
			"aws-credentials":       {},
			"mage-deploy":           {},
			"from-an-ec2-instance":  {},
			"that-image-again":      {},
		},
		DocLinks: []docLink{
			{
				Path:   "",
				Header: "#aws-credentials",
			},
			{
				Path:   "quick-start.md",
				Header: "#test-only-quick-start",
			},
		},
		EmailLinks: []string{"mailto:user@example.com"},
		ImgLinks: []string{
			".gitbook/assets/logo.png",
			".gitbook/assets/logo.png",
		},
		WebLinks: []string{
			"https://docs.docker.com/install/",
			"https://golang.org/doc/install#install",
			"https://nodejs.org/en/download/",
			"https://www.python.org/downloads/",
			"https://magefile.org/#installation",
			"https://github.com/golang-standards/project-layout",
			"https://github.com/panther-labs/panther/tree/master/api",
			"https://github.com/panther-labs/panther/tree/master/build",
			"https://github.com/99designs/aws-vault",
			"https://blog.runpanther.io/secure-multi-account-aws-access/",
			"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-custom-resources.html",
		},
	}

	assert.Equal(t, expected, summary)
}

func TestDocParseErrors(t *testing.T) {
	summary, err := parseDoc(filepath.Join("testdata", "docs", "invalid.md"))
	require.Error(t, err)
	assert.Nil(t, summary)

	expected := strings.Join([]string{
		"testdata/docs/invalid.md: 8 parsing errors:",
		fmt.Sprintf(" - header \"a1b2c3\" violates pattern %s: \"1b2\" - try adding spaces around numbers",
			titleEdgeCase.String()),
		" - duplicate header anchor #duplicate",
		" - embedded image in ![](wrong-image-format.txt) does not match expected pattern " + assetLinkPattern.String(),
		" - [empty]() has empty link target",
		" - [](example.com) is invalid - be sure web links are prefixed with \"http(s)://\" and email links are prefixed with \"mailto:\"",
		" - [](.gitbook/assets/logo.png) looks like an image, but is not prefixed with !",
		" - [](.gitbook/) is invalid - directory links are not allowed, link to a specific .md file",
		" - [](***) is invalid - non-image links must match one of these patterns:",
		webLinkPattern.String(),
		emailLinkPattern.String(),
		docLinkPattern.String(),
	}, "\n")
	assert.Equal(t, expected, err.Error())
}
