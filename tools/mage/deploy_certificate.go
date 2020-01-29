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
func uploadLocalCertificate(awsSession *session.Session) (string, error) {
	// Check if certificate has already been uploaded
	certArn, err := getExistingCertificate(awsSession)
	if err != nil {
		return "", err
	}
	if certArn != "" {
		fmt.Println("deploy: load balancer certificate already exists")
		return certArn, nil
	}
	fmt.Println("deploy: uploading load balancer certificate")

	// Ensure the certificate and key file exist. If not, create them.
	_, certErr := os.Stat(certificateFile)
	_, keyErr := os.Stat(certificateFile)
	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		if err := generateKeys(); err != nil {
			return "", err
		}
	}

	certificateFile, certificateFileErr := os.Open(certificateFile)
	if certificateFileErr != nil {
		return "", certificateFileErr
	}
	defer func() { _ = certificateFile.Close() }()

	privateKeyFile, privateKeyFileErr := os.Open(privateKeyFile)
	if privateKeyFileErr != nil {
		return "", privateKeyFileErr
	}
	defer func() { _ = privateKeyFile.Close() }()

	certificateBytes, err := ioutil.ReadAll(certificateFile)
	if err != nil {
		return "", err
	}
	privateKeyBytes, err := ioutil.ReadAll(privateKeyFile)
	if err != nil {
		return "", err
	}

	// Check if the ACM service is supported before tossing the private key out into the ether
	acmClient := acm.New(awsSession)
	_, err = acmClient.ListCertificates(&acm.ListCertificatesInput{MaxItems: aws.Int64(0)})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "SubscriptionRequiredException" {
				// ACM is not supported in this region or for this user, fall back to IAM
				fmt.Println("deploy: ACM not supported, falling back to IAM for certificate management")
				return uploadIAMCertificate(privateKeyBytes, certificateBytes, awsSession)
			}
		}
		// Some other error
		return "", err
	}
	input := &acm.ImportCertificateInput{
		Certificate: certificateBytes,
		PrivateKey:  privateKeyBytes,
		Tags: []*acm.Tag{
			{
				Key:   aws.String("Application"),
				Value: aws.String("Panther"),
			},
		},
	}
	output, err := acmClient.ImportCertificate(input)
	if err != nil {
		return "", err
	}

	return *output.CertificateArn, nil
}

// uploadIAMCertificate creates an IAM certificate resource and returns its ARN
func uploadIAMCertificate(privateKeyBytes, certificateBytes []byte, session *session.Session) (string, error) {
	iamClient := iam.New(session)
	input := &iam.UploadServerCertificateInput{
		CertificateBody:       aws.String(string(certificateBytes)),
		PrivateKey:            aws.String(string(privateKeyBytes)),
		ServerCertificateName: aws.String("PantherCertificate"),
	}
	output, err := iamClient.UploadServerCertificate(input)
	if err != nil {
		return "", err
	}

	return *output.ServerCertificateMetadata.Arn, nil
}

// getExistingCertificate checks to see if there is already an ACM/IAM certificate configured
func getExistingCertificate(awsSession *session.Session) (string, error) {
	outputs, err := getStackOutputs(awsSession, backendStack)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() != "ValidationError" || !strings.HasSuffix(awsErr.Code(), "does not exist") {
				return "", nil
			}
		}
		return "", err
	}
	if arn, ok := outputs[certificateOutputKey]; ok {
		return arn, nil
	}
	return "", nil
}

// generateKeys generates the self signed private key and certificate for HTTPS access to the web application
func generateKeys() error {
	fmt.Println("deploy: WARNING no ACM certificate ARN provided and no certificate file provided, generating a self-signed certificate")
	// Create the private key
	key, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return err
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
		return err
	}

	// Create the keys directory if it does not already exist
	err = os.MkdirAll(keysDirectory, certFilePermissions)
	if err != nil {
		return err
	}

	// PEM encode the certificate and write it to disk
	certBuffer := &bytes.Buffer{}
	err = pem.Encode(
		certBuffer,
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes},
	)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(certificateFile, certBuffer.Bytes(), certFilePermissions)
	if err != nil {
		return err
	}

	// PEM Encode the private key and write it to disk
	keyBuffer := &bytes.Buffer{}
	err = pem.Encode(
		keyBuffer,
		&pem.Block{Type: "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(privateKeyFile, keyBuffer.Bytes(), certFilePermissions)
}
