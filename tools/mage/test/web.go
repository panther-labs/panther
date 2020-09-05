package test

import (
	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/util"
)

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

var webTests = []testTask{
	{"npm run test", testWebIntegration},
	{"npm run eslint", testWebEslint},
	{"npm run tsc", testWebTsc},
}

// Test and lint web source
func Web() error {
	log = logger.Build("[test:web]")
	return runTests(webTests)
}

func testWebEslint() error {
	return util.RunWithCapturedOutput("npm", "run", "eslint")
}

func testWebTsc() error {
	return util.RunWithCapturedOutput("npm", "run", "tsc")
}

func testWebIntegration() error {
	return util.RunWithCapturedOutput("npm", "run", "test")
}
