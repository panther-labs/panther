package pantherlog

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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

func TestScanIPAddress(t *testing.T) {
	assert := require.New(t)
	w := &ValueBuffer{}

	ScanIPAddress(w, "foo")
	assert.True(w.IsEmpty())
	ScanIPAddress(w, "")
	assert.True(w.IsEmpty())
	ScanIPAddress(w, " ")
	assert.True(w.IsEmpty())
	ScanIPAddress(w, "foo@bar.baz")
	assert.True(w.IsEmpty())
	ScanIPAddress(w, "23.23.23.23")
	assert.False(w.IsEmpty())
	assert.Equal([]string{"23.23.23.23"}, w.Get(FieldIPAddress))
}

func TestScanHostname(t *testing.T) {
	assert := require.New(t)
	w := &ValueBuffer{}

	ScanHostname(w, "")
	assert.True(w.IsEmpty())
	ScanHostname(w, " ")
	assert.True(w.IsEmpty())
	ScanHostname(w, "23.23.23.23")
	assert.False(w.IsEmpty())
	assert.Equal([]string{"23.23.23.23"}, w.Get(FieldIPAddress))
	w.Reset()
	ScanHostname(w, "foo ")
	assert.False(w.IsEmpty())
	assert.Equal([]string{"foo"}, w.Get(FieldDomainName))
}

func TestScanURL(t *testing.T) {
	assert := require.New(t)
	w := &ValueBuffer{}
	ScanURL(w, "")
	assert.True(w.IsEmpty())
	ScanURL(w, " ")
	assert.True(w.IsEmpty())
	ScanURL(w, "23.23.23.23")
	assert.True(w.IsEmpty())
	ScanURL(w, "http://23.23.23.23/foo")
	assert.Equal([]string{"23.23.23.23"}, w.Get(FieldIPAddress))
	w.Reset()
	ScanURL(w, "foo ")
	assert.True(w.IsEmpty())
	ScanURL(w, "http://foo")
	assert.False(w.IsEmpty())
	assert.Equal([]string{"foo"}, w.Get(FieldDomainName))
}

func TestScanEmail(t *testing.T) {
	assert := require.New(t)
	w := &ValueBuffer{}
	ScanEmail(w, "foo")
	assert.True(w.IsEmpty())
	ScanEmail(w, "")
	assert.True(w.IsEmpty())
	ScanEmail(w, "  ")
	assert.True(w.IsEmpty())
	ScanEmail(w, "23.23.23.23")
	assert.True(w.IsEmpty())
	ScanEmail(w, "foo@bar.baz")
	assert.False(w.IsEmpty())
	ScanEmail(w, "foo@bar.baz ")
	assert.Equal([]string{"foo@bar.baz"}, w.Get(FieldEmail))
}

func TestScanDomain(t *testing.T) {
	assert := require.New(t)
	w := &ValueBuffer{}
	FieldDomainName.ScanValues(w, "")
	assert.True(w.IsEmpty())
	FieldDomainName.ScanValues(w, "  ")
	assert.True(w.IsEmpty())
	FieldDomainName.ScanValues(w, "foo ")
	assert.False(w.IsEmpty())
	assert.Equal([]string{"foo"}, w.Get(FieldDomainName))
}
