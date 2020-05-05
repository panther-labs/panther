package genericapi

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
	"errors"
	"strings"
)

// HTMLCharacterSet is the same set of characters replaced by the built-in html.EscapeString.
const HTMLCharacterSet = `'<>&"`

// ErrContainsHTML defines a standard error message if a field contains HTML characters.
var ErrContainsHTML = func() error {
	var chars []string
	for _, x := range HTMLCharacterSet {
		chars = append(chars, string(x))
	}
	return errors.New("cannot contain any of: " + strings.Join(chars, " "))
}()

// ContainsHTML is true if the string contains any of HTMLCharacterSet
//
// Such strings should be rejected for user-defined names and labels to prevent injection attacks.
func ContainsHTML(s string) bool {
	return strings.ContainsAny(s, HTMLCharacterSet)
}
