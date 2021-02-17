package awskms

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
	"crypto/sha512"
	"encoding/base64"
	"errors"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/awsutils"
)

type SignatureConfig struct {
	SigningAlgorithm string
	Filename         string
	KeyID            string
	MessageType      string
}

func NewSignatureConfig(algorithm string, keyID string, messageType string) SignatureConfig {
	return SignatureConfig{
		SigningAlgorithm: algorithm,
		KeyID:            keyID,
		MessageType:      messageType,
	}
}

func ValidateSignature(kmsClient kmsiface.KMSAPI, signatureConfig SignatureConfig, rawData []byte, signature []byte) error {
	// use hash of body in validation
	intermediateHash := sha512.Sum512(rawData)
	var computedHash []byte = intermediateHash[:]
	// The signature should be base64 encoded, decode it
	decodedSignature, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		return err
	}
	signatureVerifyInput := &kms.VerifyInput{
		KeyId:            aws.String(signatureConfig.KeyID),
		Message:          computedHash,
		MessageType:      aws.String(signatureConfig.MessageType),
		Signature:        decodedSignature,
		SigningAlgorithm: aws.String(signatureConfig.SigningAlgorithm),
	}
	result, err := kmsClient.Verify(signatureVerifyInput)
	if err != nil {
		if awsutils.IsAnyError(err, kms.ErrCodeKMSInvalidSignatureException) {
			zap.L().Error("signature verification failed", zap.Error(err))
			return err
		}
		zap.L().Warn("error validating signature", zap.Error(err))
		return err
	}
	if aws.BoolValue(result.SignatureValid) {
		zap.L().Debug("signature validation successful")
		return nil
	}
	return errors.New("error validating signature")
}
