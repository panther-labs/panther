package sophoslogs

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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
)

func LogTypes() logtypes.Group {
	return logTypes
}

var logTypes = logtypes.Must("Sophos", logtypes.ConfigJSON{
	Name:         "Sophos.Central",
	Description:  `Sophos Central events`,
	ReferenceURL: `https://support.sophos.com/support/s/article/KB-000038307?language=en_US`,
	NewEvent: func() interface{} {
		return &SophosCentralEvent{}
	},
})
