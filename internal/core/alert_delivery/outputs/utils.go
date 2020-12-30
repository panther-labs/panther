package outputs

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
	"regexp"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/pkg/errors"
)

func getAlertResponseFromSQSError(err error) *AlertDeliveryResponse {
	var awsErr awserr.Error
	if errors.As(err, &awsErr) {
		statusCode := mapSQSSendMessageErrorCodeToStatusCode(awsErr)
		return getResponse(statusCode, awsErr.Error())
	}
	return getResponse(500, err.Error())
}

func getAlertResponseFromSNSError(err error) *AlertDeliveryResponse {
	var awsErr awserr.Error
	if errors.As(err, &awsErr) {
		statusCode := mapSNSPublishErrorCodeToStatusCode(awsErr)
		return getResponse(statusCode, awsErr.Error())
	}
	return getResponse(500, err.Error())
}

// getResponse - generates a failed response that can be retried
func getResponse(statusCode int, message string) *AlertDeliveryResponse {
	return &AlertDeliveryResponse{
		StatusCode: statusCode,
		Message:    message,
		Permanent:  false,
		Success:    false,
	}
}

// Maps SNS.Publish error codes to response status codes
func mapSNSPublishErrorCodeToStatusCode(awsErr awserr.Error) int {
	switch awsErr.Code() {
	case sns.ErrCodeInvalidParameterException:
		return 400
	case sns.ErrCodeInvalidParameterValueException:
		return 400
	case sns.ErrCodeInternalErrorException:
		return 500
	case sns.ErrCodeNotFoundException:
		return 404
	case sns.ErrCodeEndpointDisabledException:
		return 403
	case sns.ErrCodePlatformApplicationDisabledException:
		return 403
	case sns.ErrCodeAuthorizationErrorException:
		return 401
	case sns.ErrCodeKMSDisabledException:
		return 403
	case sns.ErrCodeKMSInvalidStateException:
		return 409
	case sns.ErrCodeKMSNotFoundException:
		return 404
	case sns.ErrCodeKMSOptInRequired:
		return 400
	case sns.ErrCodeKMSThrottlingException:
		return 429
	case sns.ErrCodeKMSAccessDeniedException:
		return 401
	case sns.ErrCodeInvalidSecurityException:
		return 401
	default:
		return 500
	}
}

// Maps SQS.SendMessage error codes to response status codes
func mapSQSSendMessageErrorCodeToStatusCode(awsErr awserr.Error) int {
	switch awsErr.Code() {
	case sqs.ErrCodeInvalidMessageContents:
		return 400
	case sqs.ErrCodeUnsupportedOperation:
		return 403
	default:
		return 500
	}
}
func GetOpsGenieRegionalEndpoint(serviceRegion string) string {
	switch serviceRegion {
	case OpsgenieServiceRegionUS:
		return "https://api.opsgenie.com/v2/alerts"
	case OpsgenieServiceRegionEU:
		return "https://api.eu.opsgenie.com/v2/alerts"
	default:
		return "https://api.opsgenie.com/v2/alerts"
	}
}

func removeNewLines(input string) string {
	re := regexp.MustCompile(`\n`)
	return re.ReplaceAllString(input, "")
}
