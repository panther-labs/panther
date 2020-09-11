package awsutils

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import "github.com/aws/aws-sdk-go/aws/awserr"

// Method returns true if the provided error is an AWS error with any
// of the given codes.
func IsAnyError(err error, codes ...string) bool {
	awserror, ok := err.(awserr.Error)
	if !ok {
		return false
	}
	for _, code := range codes {
		if awserror.Code() == code {
			return true
		}
	}
	return false
}
