package models

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
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
	"gopkg.in/go-playground/validator.v9"
)

const (
	integrationLabelMaxLength = 32
)

var (
	integrationLabelValidatorRegex = regexp.MustCompile("^[0-9a-zA-Z- ]+$")
)

// Validator builds a custom struct validator.
func Validator() (*validator.Validate, error) {
	result := validator.New()
	if err := result.RegisterValidation("integrationLabel", validateIntegrationLabel); err != nil {
		return nil, err
	}
	if err := result.RegisterValidation("kmsKeyArn", validateKmsKeyArn); err != nil {
		return nil, err
	}
	return result, nil
}

func validateIntegrationLabel(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if len(strings.TrimSpace(value)) == 0 || len(value) > integrationLabelMaxLength {
		return false
	}
	return integrationLabelValidatorRegex.MatchString(value)
}

func validateKmsKeyArn(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	keyArn, err := arn.Parse(value)
	if err != nil {
		return false
	}

	if keyArn.Service != "kms" || !strings.HasPrefix(keyArn.Resource, "key") {
		return false
	}
	return true
}
