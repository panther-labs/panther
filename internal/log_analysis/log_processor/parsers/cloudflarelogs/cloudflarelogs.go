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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/tcodec"
)

func init() {
	tcodec.MustRegister(`cloudflare`, cloudflareCodec)

	logtypes.MustRegisterJSON(logtypes.Desc{
		Name:         "Cloudflare.HttpRequest",
		Description:  `Cloudflare http request logs`,
		ReferenceURL: `https://developers.cloudflare.com/logs/log-fields#http-requests`,
	}, func() interface{} {
		return &HTTPRequest{}
	})

	logtypes.MustRegisterJSON(logtypes.Desc{
		Name:         "Cloudflare.Spectrum",
		Description:  `Cloudflare Spectrum logs`,
		ReferenceURL: `https://developers.cloudflare.com/logs/log-fields#spectrum-events`,
	}, func() interface{} {
		return &SpectrumEvent{}
	})

	logtypes.MustRegisterJSON(logtypes.Desc{
		Name:         "Cloudflare.Firewall",
		Description:  `Cloudflare Firewall logs`,
		ReferenceURL: `https://developers.cloudflare.com/logs/log-fields#firewall-events`,
	}, func() interface{} {
		return &FirewallEvent{}
	})
}
