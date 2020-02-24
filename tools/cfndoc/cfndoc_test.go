package cfndoc

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
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatch(t *testing.T) {
	var match string
	expected := []*ResourceDoc{
		{
			Resource:      "label",
			Documentation: "doc doc",
		},
	}

	match = `<cfndoc> label doc doc</cfndoc>`
	require.Equal(t, expected, Parse(match))

	match = `<cfndoc> label 
doc doc</cfndoc>`
	require.Equal(t, expected, Parse(match))

	match = `<cfndoc> 
label 
doc doc</cfndoc>`
	require.Equal(t, expected, Parse(match))

	match = `
<cfndoc> 
label 
doc doc</cfndoc>`
	require.Equal(t, expected, Parse(match))

	match = `
<cfndoc> 
label 
doc doc
</cfndoc>

`
	require.Equal(t, expected, Parse(match))

	match = `
# <cfndoc> 
# label 
#
# doc doc
#
# </cfndoc>

`
	require.Equal(t, expected, Parse(match))

	expected = []*ResourceDoc{
		{
			Resource:      "label",
			Documentation: "# doc \n   ## doc",
		},
	}
	match = `
# <cfndoc> 
# label 
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

func TestSort(t *testing.T) {
	var match string
	expected := []*ResourceDoc{
		{
			Resource:      "label1",
			Documentation: "doc doc",
		},
		{
			Resource:      "label2",
			Documentation: "doc doc",
		},
		{
			Resource:      "label3",
			Documentation: "doc doc",
		},
	}

	match = `
<cfndoc> label2 doc doc</cfndoc>
<cfndoc> label1 doc doc</cfndoc>
<cfndoc> label3 doc doc</cfndoc>
`
	docs := Parse(match)
	sort.Sort(ByLabel(docs))
	require.Equal(t, expected, docs)
}
