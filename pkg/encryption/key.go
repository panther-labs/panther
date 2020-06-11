// Package encryption handles all KMS operations.
package encryption

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

// API defines the interface which can be used for mocking.
type API interface {
	DecryptConfig([]byte, interface{}) error
	EncryptConfig(interface{}) ([]byte, error)
}

// Key encapsulates a connection to the KMS encryption key.
type Key struct {
	ID     *string
	client kmsiface.KMSAPI
}

// The EncryptionKey must satisfy the API interface.
var _ API = (*Key)(nil)

// New creates AWS clients to interface with the encryption key.
func New(ID string, sess *session.Session) *Key {
	return &Key{ID: aws.String(ID), client: kms.New(sess)}
}
