package util

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
	"bytes"
	"fmt"
	"os"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// Returns true if the mage command is running inside the CI environment
func IsRunningInCI() bool {
	return os.Getenv("CI") != ""
}

// Run a command, capturing stdout and stderr unless the command errors or we're in verbose mode.
//
// This is helpful for tools which print unwanted info to stderr even when successful or, conversely,
// tools which output failing tests to stdout that we want to show even in non-verbose mode.
//
// Both outputs will be printed if the command returns an error.
//
// Similar to sh.Run(), except sh.Run() only hides stdout in non-verbose mode.
func RunWithCapturedOutput(cmd string, args ...string) error {
	if mg.Verbose() {
		return sh.Run(cmd, args...)
	}

	var buf bytes.Buffer
	if _, err := sh.Exec(nil, &buf, &buf, cmd, args...); err != nil {
		// The command failed - in non-verbose mode, all output has been hidden.
		// We need to print the output so the user can see the error message.
		fmt.Println(buf.String())
		return err
	}

	return nil
}
