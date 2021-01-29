package awskms

import (
	"crypto/sha512"
	"encoding/base64"
	"errors"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/panther-labs/panther/pkg/awsutils"
	"go.uber.org/zap"
)

type SignatureConfig struct {
	SigningAlgorithm string
	Filename         string
	KeyID            string
	MessageType      string
}

func NewSignatureConfig(algorithm string, signatureFilename string, keyID string, messageType string) SignatureConfig {
	return SignatureConfig{
		SigningAlgorithm: algorithm,
		Filename:         signatureFilename,
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
