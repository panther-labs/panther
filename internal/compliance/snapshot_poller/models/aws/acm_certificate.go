package aws

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"time"

	"github.com/aws/aws-sdk-go/service/acm"
)

const (
	AcmCertificateSchema = "AWS.ACM.Certificate"
)

// AcmCertificate contains all the information about an ACM certificate
type AcmCertificate struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Fields embedded from acm.CertificateDetail
	CertificateAuthorityArn *string
	DomainName              *string
	DomainValidationOptions []*acm.DomainValidation
	ExtendedKeyUsages       []*acm.ExtendedKeyUsage
	FailureReason           *string
	InUseBy                 []*string
	IssuedAt                *time.Time
	Issuer                  *string
	KeyAlgorithm            *string
	KeyUsages               []*acm.KeyUsage
	NotAfter                *time.Time
	NotBefore               *time.Time
	Options                 *acm.CertificateOptions
	RenewalEligibility      *string
	RenewalSummary          *acm.RenewalSummary
	RevocationReason        *string
	RevokedAt               *time.Time
	Serial                  *string
	SignatureAlgorithm      *string
	Status                  *string
	Subject                 *string
	SubjectAlternativeNames []*string
	Type                    *string
}
