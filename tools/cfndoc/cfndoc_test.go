package cfndoc

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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatch(t *testing.T) {
	var match string
	expected := []*ResourceDoc{
		{
			FieldName:     "Resource",
			Resource:      "label",
			Documentation: "doc doc",
		},
	}

	match = `Resource: label <cfndoc> doc doc</cfndoc>`
	require.Equal(t, expected, Parse(match))

	match = `Resource: label <cfndoc> 
doc doc</cfndoc>`
	require.Equal(t, expected, Parse(match))

	match = `Resource: label <cfndoc>
doc doc</cfndoc>`
	require.Equal(t, expected, Parse(match))

	match = `
Resource: label
<cfndoc>
doc doc</cfndoc>`
	require.Equal(t, expected, Parse(match))

	match = `
Resource: label
<cfndoc>
doc doc
</cfndoc>

`
	require.Equal(t, expected, Parse(match))

	match = `
Resource: label
# <cfndoc>
#
# doc doc
#
# </cfndoc>

`
	require.Equal(t, expected, Parse(match))

	expected = []*ResourceDoc{
		{
			FieldName:     "Resource",
			Resource:      "label",
			Documentation: "# doc \n   ## doc",
		},
	}
	match = `
Resource: label
# <cfndoc>
#
# # doc 
#   ## doc
#
# </cfndoc>

`
	require.Equal(t, expected, Parse(match))
}

func TestNoMatch(t *testing.T) {
	var expected []*ResourceDoc
	var nomatch string

	nomatch = ``
	require.Equal(t, expected, Parse(nomatch))

	nomatch = `<cfndoc> label doc`
	require.Equal(t, expected, Parse(nomatch))

	nomatch = `</cfndoc> <cfndoc>`
	require.Equal(t, expected, Parse(nomatch))
}
