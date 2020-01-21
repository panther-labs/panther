package mage

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
)

const (
	emailAlertsFromAddressOutputsKey = "EmailAlertsFromAddress"
)

func getEmailAddress(awsSession *session.Session) (string, error) {
	// Check if certificate has already been uploaded
	emailAddress, err := getExistingEmailAddress(awsSession)
	if err != nil {
		return "", err
	}

	if emailAddress != "" {
		return emailAddress, nil
	}


	sesClient := ses.New(awsSession)

	emailInput := promptUser("Enter email that will be used as alert source address. Empty string if you don't want to configure one: ", optionalEmailValidator)
	if emailInput == "" {
		return "", nil
	}

	isAlreadyVerified, err  := isAddressAlreadyVerified(sesClient, emailInput)

	if !isAlreadyVerified {
		_, err  = sesClient.VerifyEmailIdentity(&ses.VerifyEmailIdentityInput{EmailAddress: aws.String(emailInput)})
		if err != nil {
			return "", err
		}
	}

	fmt.Printf("Check [%s] inbox to verify your email\n", emailInput)
	return emailInput, nil
}

func isAddressAlreadyVerified(sesClient *ses.SES, email string) (bool, error) {
	// Check SES to see if it has been verified already
	request := &ses.GetIdentityVerificationAttributesInput{
		Identities: aws.StringSlice([]string{email}),
	}
	response, err := sesClient.GetIdentityVerificationAttributes(request)
	if err != nil {
		return false, err
	}
	verificationStatusAttributes := response.VerificationAttributes[email]
	if verificationStatusAttributes == nil {
		return false, nil
	}

	return *verificationStatusAttributes.VerificationStatus == ses.VerificationStatusSuccess, nil
}

func optionalEmailValidator(input string) error {
	if input == "" {
		return nil
	}
	return emailValidator(input)
}

func getExistingEmailAddress(awsSession *session.Session) (string, error) {
	outputs, err := getStackOutputs(awsSession, applicationStack)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() != "ValidationError" || !strings.HasSuffix(awsErr.Code(), "does not exist") {
				return "", nil
			}
		}
		return "", err
	}
	if arn, ok := outputs[emailAlertsFromAddressOutputsKey]; ok {
		return arn, nil
	}
	return "", nil
}
