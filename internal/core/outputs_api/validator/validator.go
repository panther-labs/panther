package validator

/**
 * A Cloud-Native SIEM for the Modern Security Team
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
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/api/lambda/outputs/models"
)

// Validator builds a custom struct validator.
func Validator() (*validator.Validate, error) {
	result := validator.New()
	result.RegisterStructValidation(ensureOneOutput, &models.OutputConfig{})
	if err := result.RegisterValidation("snsArn", validateAwsArn); err != nil {
		return nil, err
	}
	return result, nil
}

var outputTypes = []string{"Slack", "Sns", "PagerDuty", "Github", "Jira", "Opsgenie", "MsTeams", "Sqs", "Asana"}

func ensureOneOutput(sl validator.StructLevel) {
	input := sl.Current()

	count := 0
	for _, outputType := range outputTypes {
		if !input.FieldByName(outputType).IsNil() {
			count++
		}
	}

	if count != 1 {
		sl.ReportError(input, strings.Join(outputTypes, "|"), "", "exactly_one_output", "")
	}
}

func validateAwsArn(fl validator.FieldLevel) bool {
	fieldArn, err := arn.Parse(fl.Field().String())
	return err == nil && fieldArn.Service == "sns"
}
