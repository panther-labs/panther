package models

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

// LambdaInput is the invocation event expected by the Lambda function.
//
// Exactly one action must be specified.
type LambdaInput struct {
	GetOnboardingStatus *GetOnboardingStatusInput `json:"getOnboardingStatus"`
}

// GetOnboardingStatusInput gets the step function status
type GetOnboardingStatusInput struct {
	ExecutionArn *string `json:"executionArn" validate:"required"`
}

// GetOnboardingStatusOutput returns the state machine status
type GetOnboardingStatusOutput struct {
	Status    *string `json:"status"`
	StartDate *string `json:"startDate"`
	StopDate  *string `json:"stopDate"`
}
