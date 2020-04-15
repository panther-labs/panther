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

// AlertDeliveryError indicates whether a failed alert should be retried.
type AlertDeliveryError struct {
	// Message is the description of the problem: what went wrong.
	Message string

	// Permanent indicates whether the alert output should be retried.
	// For example, outputs which don't exist or errors creating the request are permanent failures.
	// But any error talking to the output itself can be retried by the Lambda function later.
	Permanent bool
}

func (e *AlertDeliveryError) Error() string { return e.Message }
