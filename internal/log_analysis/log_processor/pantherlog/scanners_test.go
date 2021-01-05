package pantherlog

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
	"crypto/md5"  // nolint (gosec)
	"crypto/sha1" // nolint (gosec)
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

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

func TestScanDomainName(t *testing.T) {
	assert := require.New(t)
	w := &ValueBuffer{}
	ScanDomainName(w, "")
	assert.True(w.IsEmpty())
	ScanDomainName(w, "  ")
	assert.True(w.IsEmpty())
	ScanDomainName(w, "foo ")
	assert.False(w.IsEmpty())
	assert.Equal([]string{"foo"}, w.Get(FieldDomainName))

	// test puny encoded
	w = &ValueBuffer{}
	ScanDomainName(w, "xn--fa-hia.com")
	assert.False(w.IsEmpty())
	assert.Equal([]string{"faß.com"}, w.Get(FieldDomainName))
}

func TestScanMD5Hash(t *testing.T) {
	assert := require.New(t)
	w := &ValueBuffer{}
	h := md5.New() // nolint (gosec)
	_, _ = io.WriteString(h, "The fog is getting thicker!")
	hash := fmt.Sprintf("%x", h.Sum(nil))
	ScanMD5Hash(w, "")
	assert.True(w.IsEmpty())
	ScanMD5Hash(w, "  ")
	assert.True(w.IsEmpty())
	ScanMD5Hash(w, "foo ")
	assert.True(w.IsEmpty())
	ScanMD5Hash(w, hash)
	assert.False(w.IsEmpty())
	assert.Equal([]string{hash}, w.Get(FieldMD5Hash))
}

func TestScanSHA1Hash(t *testing.T) {
	assert := require.New(t)
	w := &ValueBuffer{}
	h := sha1.New() // nolint (gosec)
	_, _ = io.WriteString(h, "The fog is getting thicker!")
	hash := fmt.Sprintf("%x", h.Sum(nil))
	ScanSHA1Hash(w, "")
	assert.True(w.IsEmpty())
	ScanSHA1Hash(w, "  ")
	assert.True(w.IsEmpty())
	ScanSHA1Hash(w, "foo ")
	assert.True(w.IsEmpty())
	ScanSHA1Hash(w, hash)
	assert.False(w.IsEmpty())
	assert.Equal([]string{hash}, w.Get(FieldSHA1Hash))
}

func TestScanSHA256Hash(t *testing.T) {
	assert := require.New(t)
	w := &ValueBuffer{}
	h := sha256.New()
	_, _ = io.WriteString(h, "The fog is getting thicker!")
	hash := fmt.Sprintf("%x", h.Sum(nil))
	ScanSHA256Hash(w, "")
	assert.True(w.IsEmpty())
	ScanSHA256Hash(w, "  ")
	assert.True(w.IsEmpty())
	ScanSHA256Hash(w, "foo ")
	assert.True(w.IsEmpty())
	ScanSHA256Hash(w, hash)
	assert.False(w.IsEmpty())
	assert.Equal([]string{hash}, w.Get(FieldSHA256Hash))
}

func TestIsHex(t *testing.T) {
	assert := require.New(t)
	var tests = []struct {
		s     string
		isHex bool
	}{
		{"", false},
		{"abcdefghijk", false},
		{"ABCDEFGHIJK", false},
		{"@!#", false},

		{"0123456789", true},
		{"abcdef", true},
		{"ABCDEF", true},
	}
	for _, test := range tests {
		assert.True(test.isHex == isHex(test.s))
	}
}
