package aws

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/acm/acmiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// Set as variables to be overridden in testing
var (
	AcmClientFunc = setupAcmClient
)

func setupAcmClient(sess *session.Session, cfg *aws.Config) interface{} {
	return acm.New(sess, cfg)
}

func getAcmClient(pollerResourceInput *awsmodels.ResourcePollerInput,
	region string) (acmiface.ACMAPI, error) {

	client, err := getClient(pollerResourceInput, AcmClientFunc, "acm", region)
	if err != nil {
		return nil, err
	}

	return client.(acmiface.ACMAPI), nil
}

// PollACMCertificate a single ACM certificate resource
func PollACMCertificate(
	pollerInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	client, err := getAcmClient(pollerInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}

	snapshot, err := buildAcmCertificateSnapshot(client, scanRequest.ResourceID)
	if err != nil {
		return nil, err
	}
	if snapshot == nil {
		return nil, nil
	}
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.AccountID = aws.String(resourceARN.AccountID)

	return snapshot, nil
}

// listCertificates returns all ACM certificates in the account
func listCertificates(acmSvc acmiface.ACMAPI, nextMarker *string) (acmCerts []*acm.CertificateSummary, marker *string, err error) {
	err = acmSvc.ListCertificatesPages(&acm.ListCertificatesInput{
		NextToken: nextMarker,
		MaxItems:  aws.Int64(int64(defaultBatchSize)),
	}, func(page *acm.ListCertificatesOutput, _ bool) bool {
		return certificateIterator(page, &acmCerts, &marker)
	})

	if err != nil {
		return nil, nil, errors.Wrap(err, "ACM.ListCertificatesPages")
	}

	return
}

func certificateIterator(page *acm.ListCertificatesOutput, acmCerts *[]*acm.CertificateSummary, marker **string) bool {
	*acmCerts = append(*acmCerts, page.CertificateSummaryList...)
	*marker = page.NextToken
	return len(*acmCerts) < defaultBatchSize
}

// describeCertificates provides detailed information for a given ACM certificate
func describeCertificate(acmSvc acmiface.ACMAPI, arn *string) (*acm.CertificateDetail, error) {
	out, err := acmSvc.DescribeCertificate(&acm.DescribeCertificateInput{CertificateArn: arn})
	if err != nil {
		return nil, errors.Wrapf(err, "ACM.DescribeCertificate: %s", aws.StringValue(arn))
	}

	return out.Certificate, nil
}

// listTagsForCertificate returns the tags for an ACM certificate
func listTagsForCertificate(acmSvc acmiface.ACMAPI, arn *string) ([]*acm.Tag, error) {
	out, err := acmSvc.ListTagsForCertificate(&acm.ListTagsForCertificateInput{CertificateArn: arn})
	if err != nil {
		return nil, errors.Wrapf(err, "ACM.ListTagsForCertificate: %s", aws.StringValue(arn))
	}

	return out.Tags, nil
}

// buildAcmCertificateSnapshot returns a complete snapshot of an ACM certificate
func buildAcmCertificateSnapshot(acmSvc acmiface.ACMAPI, certificateArn *string) (*awsmodels.AcmCertificate, error) {
	if certificateArn == nil {
		return nil, nil
	}

	metadata, err := describeCertificate(acmSvc, certificateArn)
	if err != nil {
		return nil, err
	}

	acmCertificate := &awsmodels.AcmCertificate{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   certificateArn,
			ResourceType: aws.String(awsmodels.AcmCertificateSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			ARN:  certificateArn,
			Name: metadata.DomainName,
		},
		CertificateAuthorityArn: metadata.CertificateAuthorityArn,
		DomainName:              metadata.DomainName,
		DomainValidationOptions: metadata.DomainValidationOptions,
		ExtendedKeyUsages:       metadata.ExtendedKeyUsages,
		FailureReason:           metadata.FailureReason,
		InUseBy:                 metadata.InUseBy,
		IssuedAt:                metadata.IssuedAt,
		Issuer:                  metadata.Issuer,
		KeyAlgorithm:            metadata.KeyAlgorithm,
		KeyUsages:               metadata.KeyUsages,
		NotAfter:                metadata.NotAfter,
		NotBefore:               metadata.NotBefore,
		Options:                 metadata.Options,
		RenewalEligibility:      metadata.RenewalEligibility,
		RenewalSummary:          metadata.RenewalSummary,
		RevocationReason:        metadata.RevocationReason,
		RevokedAt:               metadata.RevokedAt,
		Serial:                  metadata.Serial,
		SignatureAlgorithm:      metadata.SignatureAlgorithm,
		Status:                  metadata.Status,
		Subject:                 metadata.Subject,
		SubjectAlternativeNames: metadata.SubjectAlternativeNames,
		Type:                    metadata.Type,
	}

	if *metadata.Type == "AMAZON_CREATED" {
		acmCertificate.TimeCreated = metadata.CreatedAt
	} else if *metadata.Type == "IMPORTED" {
		acmCertificate.TimeCreated = metadata.ImportedAt
	}

	tags, err := listTagsForCertificate(acmSvc, certificateArn)
	if err != nil {
		return nil, err
	}
	acmCertificate.Tags = utils.ParseTagSlice(tags)

	return acmCertificate, nil
}

// PollAcmCertificates gathers information on each ACM Certificate for an AWS account.
func PollAcmCertificates(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting ACM Certificate resource poller")

	acmSvc, err := getAcmClient(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all certificates
	certificates, marker, err := listCertificates(acmSvc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	// For each certificate, build a snapshot of that certificate
	resources := make([]apimodels.AddResourceEntry, 0, len(certificates))
	for _, certificateSummary := range certificates {
		acmCertificateSnapshot, err := buildAcmCertificateSnapshot(acmSvc, certificateSummary.CertificateArn)
		if err != nil {
			return nil, nil, err
		}
		acmCertificateSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		acmCertificateSnapshot.Region = pollerInput.Region

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      acmCertificateSnapshot,
			ID:              *acmCertificateSnapshot.ResourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.AcmCertificateSchema,
		})
	}

	return resources, marker, nil
}
