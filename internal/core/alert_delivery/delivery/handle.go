package delivery

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
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

func mustParseInt(text string) int {
	val, err := strconv.Atoi(text)
	if err != nil {
		panic(err)
	}
	return val
}

func getMaxRetryDuration() time.Duration {
	return time.Duration(mustParseInt(os.Getenv("ALERT_RETRY_DURATION_MINS"))) * time.Minute
}

// HandleAlerts sends each alert to its outputs and puts failed alerts back on the queue to retry.
func HandleAlerts(alerts []*models.Alert) {
	var failedAlerts []*models.Alert

	zap.L().Info("starting processing alerts", zap.Int("alerts", len(alerts)))

	for _, alert := range alerts {
		if !dispatch(alert) {
			if time.Since(alert.CreatedAt) > getMaxRetryDuration() {
				zap.L().Error(
					"alert delivery permanently failed, exceeded max retry duration",
					zap.Strings("failedOutputs", alert.OutputIDs),
					zap.Time("alertCreatedAt", alert.CreatedAt),
					zap.String("policyId", alert.AnalysisID),
					zap.String("severity", alert.Severity),
				)
			} else {
				zap.L().Warn("will retry delivery of alert",
					zap.String("policyId", alert.AnalysisID),
					zap.String("severity", alert.Severity),
				)
				failedAlerts = append(failedAlerts, alert)
			}
		}
	}

	if len(failedAlerts) > 0 {
		retry(failedAlerts)
	}
}
