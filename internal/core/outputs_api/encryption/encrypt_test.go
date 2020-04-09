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
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/stretchr/testify/assert"

	"github.com/panther-labs/panther/pkg/genericapi"
)

type mockEncryptClient struct {
	kmsiface.KMSAPI
	err bool
}

func (m *mockEncryptClient) Encrypt(input *kms.EncryptInput) (*kms.EncryptOutput, error) {
	if m.err {
		return nil, errors.New("internal error")
	}
	return &kms.EncryptOutput{CiphertextBlob: []byte("super secret")}, nil
}

func TestEncryptConfigMarshalError(t *testing.T) {
	key := &Key{client: &mockEncryptClient{}}
	result, err := key.EncryptConfig(key.EncryptConfig)
	assert.Nil(t, result)
	assert.NotNil(t, err.(*genericapi.InternalError))
}

func TestEncryptConfigServiceError(t *testing.T) {
	key := &Key{client: &mockEncryptClient{err: true}}
	result, err := key.EncryptConfig("access-token")
	assert.Nil(t, result)
	assert.NotNil(t, err.(*genericapi.AWSError))
}

func TestEncrypt(t *testing.T) {
	key := &Key{client: &mockEncryptClient{}}
	result, err := key.EncryptConfig("access-token")
	assert.NotNil(t, result)
	assert.Nil(t, err)
}
