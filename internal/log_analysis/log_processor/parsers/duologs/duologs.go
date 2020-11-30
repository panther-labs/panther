package duologs

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

// We use an immediately called function to register the time decoder before building the logtype entries.
var logTypes = func() logtypes.Group {
	return logtypes.Must("Duo",
		logtypes.ConfigJSON{
			Name: TypeAuthentication,
			// nolint:lll
			Description:  `Duo authentication log events(v2).`,
			ReferenceURL: `https://duo.com/docs/adminapi#authentication-logs`,
			NewEvent: func() interface{} {
				return &AuthenticationLog{}
			},
		},

		logtypes.ConfigJSON{
			Name: TypeAdministrator,
			// nolint:lll
			Description:  `Duo administrator log events.`,
			ReferenceURL: `https://duo.com/docs/adminapi#administrator-logs`,
			NewEvent: func() interface{} {
				return &AdministratorLog{}
			},
		},
		logtypes.ConfigJSON{
			Name: TypeTelephony,
			// nolint:lll
			Description:  `Duo telephony log events.`,
			ReferenceURL: `https://duo.com/docs/adminapi#telephony-logs`,
			NewEvent: func() interface{} {
				return &TelephonyLog{}
			},
		},
		logtypes.ConfigJSON{
			Name: TypeOfflineEnrollment,
			// nolint:lll
			Description:  `Duo Authentication for Windows Logon offline enrollment events.`,
			ReferenceURL: `https://duo.com/docs/adminapi#offline-enrollment-logs`,
			NewEvent: func() interface{} {
				return &OfflineEnrollmentLog{}
			},
		},
	)
}()
