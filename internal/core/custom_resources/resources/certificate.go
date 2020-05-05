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
	"time"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/iam"
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

		return certArn, map[string]interface{}{"CertificateArn": certArn}, nil

	case cfn.RequestUpdate:
		// There is nothing to update on an existing certificate.
		certArn := event.PhysicalResourceID
		return certArn, map[string]interface{}{"CertificateArn": certArn}, nil

	case cfn.RequestDelete:
		return event.PhysicalResourceID, nil, deleteCert(event.PhysicalResourceID)

	default:
		return "", nil, fmt.Errorf("unknown request type: %v", event.RequestType)
	}
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
	output, err := getAcmClient().ImportCertificate(&acm.ImportCertificateInput{
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
	output, err := getIamClient().UploadServerCertificate(&iam.UploadServerCertificateInput{
		CertificateBody: aws.String(string(cert)),
		Path:            aws.String("/panther/" + *getSession().Config.Region + "/"),
		PrivateKey:      aws.String(string(privateKey)),
		ServerCertificateName: aws.String(
			"PantherCertificate-" + time.Now().Format("2006-01-02T15-04-05")),
	})

	if err != nil {
		return "", err
	}
	return *output.ServerCertificateMetadata.Arn, nil
}

// Generate a self-signed certificate and private key.
func generateKeys() ([]byte, []byte, error) {
	now := time.Now()
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

func deleteCert(certArn string) error {
	parsedArn, err := arn.Parse(certArn)
	if err != nil {
		return fmt.Errorf("failed to parse %s as arn: %v", certArn, err)
	}

	switch parsedArn.Service {
	case "acm":
		_, err := getAcmClient().DeleteCertificate(
			&acm.DeleteCertificateInput{CertificateArn: &certArn})
		return err
	case "iam":
		_, err := getIamClient().DeleteServerCertificate(
			&iam.DeleteServerCertificateInput{ServerCertificateName: &certArn})
		return err
	default:
		return fmt.Errorf("%s is not an ACM/IAM cert", certArn)
	}
}
