package mage

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/iam"
)

const (
	keysDirectory        = "keys"
	certificateFile      = keysDirectory + "/panther-tls-public.crt"
	privateKeyFile       = keysDirectory + "/panther-tls-private.key"
	keyLength            = 2048
	certFilePermissions  = 0700
	certificateOutputKey = "WebApplicationCertificateArn"
)

// Upload a local self-signed TLS certificate to ACM. Only needs to happen once per installation
//
// In regions/partitions where ACM is not supported, we fall back to IAM certificate management.
func uploadLocalCertificate(awsSession *session.Session) string {
	// Check if certificate has already been uploaded
	if certArn := getExistingCertificate(awsSession); certArn != nil {
		logger.Debugf("deploy: load balancer certificate %s already exists", *certArn)
		return *certArn
	}

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
		logger.Fatalf("ACM certificate import failed: %v", err)
	}

	return *output.CertificateArn
}

// getExistingCertificate checks to see if there is already an ACM/IAM certificate configured
func getExistingCertificate(awsSession *session.Session) *string {
	outputs, err := getStackOutputs(awsSession, backendStack)
	if err != nil {
		if strings.Contains(err.Error(), "Stack with id "+backendStack+" does not exist") {
			return nil
		}
		logger.Fatal(err)
	}
	if arn, ok := outputs[certificateOutputKey]; ok {
		return &arn
	}
	return nil
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

	// Create the keys directory if it does not already exist
	if err = os.MkdirAll(keysDirectory, certFilePermissions); err != nil {
		return fmt.Errorf("failed to create keys directory %s: %v", keysDirectory, err)
	}

	// PEM encode the certificate and write it to disk
	var certBuffer bytes.Buffer
	if err = pem.Encode(&certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return fmt.Errorf("cert encoding failed: %v", err)
	}
	if err = ioutil.WriteFile(certificateFile, certBuffer.Bytes(), certFilePermissions); err != nil {
		return fmt.Errorf("failed to save cert %s: %v", certificateFile, err)
	}

	// PEM Encode the private key and write it to disk
	var keyBuffer bytes.Buffer
	err = pem.Encode(&keyBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return fmt.Errorf("key encoding failed: %v", err)
	}
	if err = ioutil.WriteFile(privateKeyFile, keyBuffer.Bytes(), certFilePermissions); err != nil {
		return fmt.Errorf("failed to save key %s: %v", privateKeyFile, err)
	}

	return nil
}

// uploadIAMCertificate creates an IAM certificate resource and returns its ARN
func uploadIAMCertificate(awsSession *session.Session) string {
	certName := "PantherCertificate-" + time.Now().Format("2006-01-02T15-04-05")
	input := &iam.UploadServerCertificateInput{
		CertificateBody:       aws.String(string(readFile(certificateFile))),
		PrivateKey:            aws.String(string(readFile(privateKeyFile))),
		ServerCertificateName: aws.String(certName),
	}
	output, err := iam.New(awsSession).UploadServerCertificate(input)
	if err != nil {
		logger.Fatalf("failed to upload cert to IAM: %v", err)
	}

	return *output.ServerCertificateMetadata.Arn
}
