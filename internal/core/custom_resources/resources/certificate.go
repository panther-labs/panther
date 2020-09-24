package resources

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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/cenkalti/backoff/v4"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const keyLength = 2048

// Try to upload a self-signed ACM certificate, falling back to an IAM server certificate if necessary.
func customCertificate(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate:
		cert, privateKey, err := generateKeys()
		if err != nil {
			return "", nil, err
		}

		certArn, err := importCert(cert, privateKey)
		if err != nil {
			return "", nil, err
		}

		return certArn, map[string]interface{}{"Arn": certArn}, nil

	case cfn.RequestDelete:
		return event.PhysicalResourceID, nil, deleteCert(event.PhysicalResourceID)

	default:
		// There is nothing to update on an existing certificate.
		certArn := event.PhysicalResourceID
		return certArn, map[string]interface{}{"Arn": certArn}, nil
	}
}

// Generate a self-signed certificate and private key.
func generateKeys() ([]byte, []byte, error) {
	now := time.Now().UTC()
	certificateTemplate := x509.Certificate{
		BasicConstraintsValid: true,
		// AWS will not attach a certificate that does not have a domain specified
		// example.com is reserved by IANA and is not available for registration so there is no risk
		// of confusion about us trying to MITM someone (ref: https://www.iana.org/domains/reserved)
		DNSNames:     []string{"example.com"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		NotAfter:     now.Add(time.Hour * 24 * 365),
		NotBefore:    now,
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Panther User"},
		},
	}

	// Generate the key pair.
	// NOTE: This key is never saved to disk
	key, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return nil, nil, fmt.Errorf("rsa key generation failed: %v", err)
	}

	// Create the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, &certificateTemplate, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("x509 cert creation failed: %v", err)
	}

	// PEM encode the certificate
	var certBuffer bytes.Buffer
	if err = pem.Encode(&certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return nil, nil, fmt.Errorf("cert encoding failed: %v", err)
	}

	// PEM encode the private key
	var keyBuffer bytes.Buffer
	err = pem.Encode(&keyBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return nil, nil, fmt.Errorf("key encoding failed: %v", err)
	}

	return certBuffer.Bytes(), keyBuffer.Bytes(), nil
}

// Import a cert in ACM if possible, falling back to IAM if necessary. Returns the certificate arn.
func importCert(cert, privateKey []byte) (string, error) {
	certArn, err := importAcmCert(cert, privateKey)
	if err == nil {
		return certArn, nil
	}

	zap.L().Warn("ACM import failed, falling back to IAM", zap.Error(err))
	return importIamCert(cert, privateKey)
}

func importAcmCert(cert, privateKey []byte) (string, error) {
	output, err := acmClient.ImportCertificate(&acm.ImportCertificateInput{
		Certificate: cert,
		PrivateKey:  privateKey,
		Tags: []*acm.Tag{
			{
				Key:   aws.String("Application"),
				Value: aws.String("Panther"),
			},
		},
	})

	if err != nil {
		return "", err
	}
	return *output.CertificateArn, nil
}

func importIamCert(cert, privateKey []byte) (string, error) {
	output, err := iamClient.UploadServerCertificate(&iam.UploadServerCertificateInput{
		CertificateBody: aws.String(string(cert)),
		Path:            aws.String("/panther/" + *awsSession.Config.Region + "/"),
		PrivateKey:      aws.String(string(privateKey)),
		ServerCertificateName: aws.String(
			"PantherCertificate-" + time.Now().Format("2006-01-02T15-04-05")),
	})

	if err != nil {
		return "", err
	}

	// It takes quite a few seconds for IAM server certificates to be visible to other services like ELB.
	// Without this sleep, the ELB which depends on the custom cert fails to create with:
	// 	  Certificate 'arn:aws:iam::XXXX:server-certificate/panther/...' not found
	//
	// NOTE: we can make this a parameter in the future if we need to use this resource more than once.
	// For example,
	//   Type: Custom::Certificate
	//   Properties:
	//     WaitAfterCreation: 10s
	time.Sleep(10 * time.Second)
	return *output.ServerCertificateMetadata.Arn, nil
}

func deleteCert(certArn string) error {
	parsedArn, err := arn.Parse(certArn)
	if err != nil {
		// If creation fails before the cert was successfully created, the resourceID will be "error"
		zap.L().Warn("failed to parse physicalResourceId as arn - skipping delete", zap.Error(err))
		return nil
	}

	backoffConfig := backoff.NewExponentialBackOff()
	backoffConfig.MaxInterval = 30 * time.Second
	backoffConfig.MaxElapsedTime = 5 * time.Minute

	switch parsedArn.Service {
	case "acm":
		input := &acm.DeleteCertificateInput{CertificateArn: &certArn}

		deleteFunc := func() error {
			_, err := acmClient.DeleteCertificate(input)
			if err == nil {
				return nil
			}

			var awsErr awserr.Error
			if errors.As(err, &awsErr) {
				switch awsErr.Code() {
				case acm.ErrCodeResourceNotFoundException:
					zap.L().Info("ACM certificate has already been deleted")
					return nil
				case acm.ErrCodeResourceInUseException:
					// The certificate is still in use - log a warning and try again with backoff.
					// When the cert is deleted in the same stack it is used, it can take awhile for ACM
					// to realize it's safe to delete.
					zap.L().Warn("ACM certificate still in use", zap.Error(err))
					return err
				}
			}

			// Some other error - don't retry
			return backoff.Permanent(err)
		}

		return backoff.Retry(deleteFunc, backoffConfig)

	case "iam":
		// Pull the certificate name out of the arn. Example:
		//     arn:aws:iam::XXXX:server-certificate/panther/us-east-1/PantherCertificate-2020-04-27T17-23-11
		// IAM cert names cannot contain "/", so we know everything after the last / is the name
		split := strings.Split(parsedArn.Resource, "/")
		name := split[len(split)-1]
		input := &iam.DeleteServerCertificateInput{ServerCertificateName: &name}

		deleteFunc := func() error {
			_, err := iamClient.DeleteServerCertificate(input)
			if err == nil {
				return nil
			}

			var awsErr awserr.Error
			if errors.As(err, &awsErr) {
				switch awsErr.Code() {
				case iam.ErrCodeNoSuchEntityException:
					zap.L().Info("IAM server certificate has already been deleted")
					return nil
				case iam.ErrCodeDeleteConflictException:
					// The certificate is still in use - log a warning and try again with backoff.
					// When the cert is deleted in the same stack it is used, it can take awhile for IAM
					// to realize it's safe to delete.
					zap.L().Warn("iam server certificate still in use", zap.Error(err))
					return err
				}
			}
			// Some other error - don't retry
			return backoff.Permanent(err)
		}

		return backoff.Retry(deleteFunc, backoffConfig)

	default:
		return fmt.Errorf("%s is not an ACM/IAM cert", certArn)
	}
}
