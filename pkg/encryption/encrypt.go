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
	"github.com/aws/aws-sdk-go/service/kms"
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/pkg/genericapi"
)

// EncryptConfig uses KMS to encrypt an output configuration.
func (key *Key) EncryptConfig(config interface{}) ([]byte, error) {
	body, err := jsoniter.Marshal(config)
	if err != nil {
		return nil, &genericapi.InternalError{
			Message: "failed to marshal config to json " + err.Error()}
	}

	response, err := key.client.Encrypt(&kms.EncryptInput{KeyId: key.ID, Plaintext: body})
	if err != nil {
		return nil, &genericapi.AWSError{Method: "kms.Encrypt", Err: err}
	}

	return response.CiphertextBlob, nil
}
