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

type mockDecryptClient struct {
	kmsiface.KMSAPI
	returnPlaintext []byte
	err             bool
}

func (m *mockDecryptClient) Decrypt(input *kms.DecryptInput) (*kms.DecryptOutput, error) {
	if m.err {
		return nil, errors.New("internal error")
	}
	return &kms.DecryptOutput{Plaintext: m.returnPlaintext}, nil
}

func TestDecryptConfigServiceError(t *testing.T) {
	key := &Key{client: &mockDecryptClient{err: true}}
	err := key.DecryptConfig([]byte("ciphertext"), nil)
	assert.NotNil(t, err.(*genericapi.AWSError))
}

func TestDecryptConfigUnmarshalError(t *testing.T) {
	type detail struct {
		Name string `json:"name"`
	}
	key := &Key{client: &mockDecryptClient{returnPlaintext: []byte("access-token")}}
	err := key.DecryptConfig([]byte("ciphertext"), &detail{})
	assert.NotNil(t, err.(*genericapi.InternalError))
}

func TestDecryptConfig(t *testing.T) {
	type detail struct {
		Name string `json:"name"`
	}
	key := &Key{client: &mockDecryptClient{returnPlaintext: []byte("{\"name\": \"panther\"}")}}
	var output detail
	assert.Nil(t, key.DecryptConfig([]byte("ciphertext"), &output))
	assert.Equal(t, detail{Name: "panther"}, output)
}
