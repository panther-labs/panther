package cloudflarelogs

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
	"time"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/tcodec"
)

func LogTypes() logtypes.Group {
	return logTypes
}

// We use an immediately called function to register the time decoder before building the logtype entries.
var logTypes = func() logtypes.Group {
	tcodec.MustRegister(`cloudflare`, tcodec.Join(
		&timeDecoder{},
		tcodec.LayoutCodec(time.RFC3339), // encoder
	))
	return logtypes.Must("Cloudflare",
		logtypes.ConfigJSON{
			Name: "Cloudflare.HttpRequest",
			// nolint:lll
			Description:  `Cloudflare http request logs. When selecting event fields on the Cloudflare UI, make sure you include the "EdgeStartTimestamp" field as it is required by Panther.`,
			ReferenceURL: `https://developers.cloudflare.com/logs/log-fields#http-requests`,
			NewEvent: func() interface{} {
				return &HTTPRequest{}
			},
		},
		logtypes.ConfigJSON{
			Name: "Cloudflare.Spectrum",
			// nolint:lll
			Description:  `Cloudflare Spectrum logs. When selecting event fields on the Cloudflare UI, make sure you include the "Timestamp" field as it is required by Panther.`,
			ReferenceURL: `https://developers.cloudflare.com/logs/log-fields#spectrum-events`,
			NewEvent: func() interface{} {
				return &SpectrumEvent{}
			},
		},
		logtypes.ConfigJSON{
			Name: "Cloudflare.Firewall",
			// nolint:lll
			Description:  `Cloudflare Firewall logs. When selecting event fields on the Cloudflare UI, make sure you include the "Datetime" field as it is required by Panther.`,
			ReferenceURL: `https://developers.cloudflare.com/logs/log-fields#firewall-events`,
			NewEvent: func() interface{} {
				return &FirewallEvent{}
			},
		},
	)
}()
