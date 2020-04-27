package mage

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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/iam"

	"github.com/panther-labs/panther/tools/config"
)

const (
	keysDirectory       = "keys"
	certificateFile     = keysDirectory + "/panther-tls-public.crt"
	privateKeyFile      = keysDirectory + "/panther-tls-private.key"
	keyLength           = 2048
	certFilePermissions = 0700
)

// Returns the certificate arn for the bootstrap stack. One of:
//
// 1) The settings file, if it's specified
// 2) The bootstrap stack output (existingCertArn)
// 3) Uploading an ACM or IAM cert
func certificateArn(awsSession *session.Session, settings *config.PantherConfig, existingCertArn string) string {
	if settings.Web.CertificateArn != "" {
		// Always use the value in the settings file first, if it exists
		return settings.Web.CertificateArn
	}

	// If the bootstrap stack already exists and has a certificate arn, use that
	if existingCertArn != "" {
		return existingCertArn
	}

	// If the stack outputs are blank, it never deployed successfully - upload a new cert
	return uploadLocalCertificate(awsSession)
}

// Upload a local self-signed TLS certificate to ACM. Only needs to happen once per installation
//
// In regions/partitions where ACM is not supported, we fall back to IAM certificate management.
func uploadLocalCertificate(awsSession *session.Session) string {
	// Ensure the certificate and key file exist. If not, create them.
	_, certErr := os.Stat(certificateFile)
	_, keyErr := os.Stat(privateKeyFile)
	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		if err := generateKeys(); err != nil {
			logger.Fatal(err)
		}
	}

	logger.Infof("deploy: uploading load balancer certificate %s with key %s", certificateFile, privateKeyFile)

	// Check if the ACM service is supported before tossing the private key out into the ether
	acmClient := acm.New(awsSession)
	if _, err := acmClient.ListCertificates(&acm.ListCertificatesInput{MaxItems: aws.Int64(1)}); err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "SubscriptionRequiredException" {
			// ACM is not supported in this region or for this user, fall back to IAM
			logger.Warn("deploy: ACM not supported, falling back to IAM for certificate management")
			return uploadIAMCertificate(awsSession)
		}
		logger.Fatalf("failed to list certificates: %v", err)
	}

	output, err := acmClient.ImportCertificate(&acm.ImportCertificateInput{
		Certificate: readFile(certificateFile),
		PrivateKey:  readFile(privateKeyFile),
		Tags: []*acm.Tag{
			{
				Key:   aws.String("Application"),
				Value: aws.String("Panther"),
			},
		},
	})

	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "LimitExceededException" {
				logger.Warn("deploy: ACM certificate import limit reached, falling back to IAM for certificate management")
				return uploadIAMCertificate(awsSession)
			}
		}
		logger.Fatalf("ACM certificate import failed: %v", err)
	}

	return *output.CertificateArn
}

// generateKeys generates the self signed private key and certificate for HTTPS access to the web application
func generateKeys() error {
	logger.Warn("deploy: no certificate provided in config nor in keys/, generating a self-signed certificate")
	// Create the private key
	key, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return fmt.Errorf("rsa key generation failed: %v", err)
	}

	// Setup the certificate template
	certificateTemplate := x509.Certificate{
		BasicConstraintsValid: true,
		// AWS will not attach a certificate that does not have a domain specified
		// example.com is reserved by IANA and is not available for registration so there is no risk
		// of confusion about us trying to MITM someone (ref: https://www.iana.org/domains/reserved)
		DNSNames:     []string{"example.com"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		NotBefore:    time.Now(),
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Panther User"},
		},
	}

	// Create the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, &certificateTemplate, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("x509 cert creation failed: %v", err)
	}

	// PEM encode the certificate and write it to disk
	var certBuffer bytes.Buffer
	if err = pem.Encode(&certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return fmt.Errorf("cert encoding failed: %v", err)
	}
	if err = writeFile(certificateFile, certBuffer.Bytes()); err != nil {
		return err
	}

	// PEM Encode the private key and write it to disk
	var keyBuffer bytes.Buffer
	err = pem.Encode(&keyBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return fmt.Errorf("key encoding failed: %v", err)
	}
	return writeFile(privateKeyFile, keyBuffer.Bytes())
}

// uploadIAMCertificate creates an IAM certificate resource and returns its ARN
func uploadIAMCertificate(awsSession *session.Session) string {
	certName := "PantherCertificate-" + time.Now().Format("2006-01-02T15-04-05")
	input := &iam.UploadServerCertificateInput{
		CertificateBody:       aws.String(string(readFile(certificateFile))),
		Path:                  aws.String("/panther/" + *awsSession.Config.Region + "/"),
		PrivateKey:            aws.String(string(readFile(privateKeyFile))),
		ServerCertificateName: aws.String(certName),
	}
	output, err := iam.New(awsSession).UploadServerCertificate(input)
	if err != nil {
		logger.Fatalf("failed to upload cert to IAM: %v", err)
	}

	return *output.ServerCertificateMetadata.Arn
}
