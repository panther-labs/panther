package merger

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
	"crypto/sha1" // nolint: gosec
	"time"
)

// AlertNotification models a notification sent to Alert merger
type AlertNotification struct {
	RuleID        *string    `json:"ruleId"`
	RuleVersionID *string    `json:"ruleVersionId"`
	Event         *string    `json:"event"`
	Timestamp     *time.Time `json:"timestamp"`
}

// MatchedEvent represents an event matched by the Panther rule engine
type MatchedEvent struct {
	EventHash [sha1.Size]byte `json:"eventHash"`
	Timestamp *time.Time      `json:"timestamp"`
	Event     *string         `json:"event"`
}
