package email

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
	"strconv"
	"time"

	"github.com/matcornic/hermes"
)

var (
	// The logo is fetched from panther-public cloudfront CDN
	pantherEmailLogo = "https://d14d54mfia7r7w.cloudfront.net/panther-email-logo-white.png"
	// PantherEmailTemplate is used as a boilerplate for Panther themed email
	PantherEmailTemplate = hermes.Hermes{
		Theme: new(hermes.Flat),
		Product: hermes.Product{
			// Appears in header & footer of e-mails
			Name:      "Panther",
			Link:      "runpanther.io",
			Copyright: "Copyright © " + strconv.Itoa(time.Now().Year()) + " Panther Labs Inc. All rights reserved.",
			Logo:      pantherEmailLogo,
		},
	}
)
