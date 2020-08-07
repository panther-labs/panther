/*
Utility package to read input from terminal.
*/
package prompt

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
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// Read will prompt the user for a string input, all validators must pass to return
func Read(prompt string, validators ...func(string) error) string {
	reader := bufio.NewReader(os.Stdin)

rePrompt:
	for {
		fmt.Print(prompt)
		result, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("read string failed: %v\n", err)
			continue
		}

		result = strings.TrimSpace(result)
		for _, validator := range validators {
			if err := validator(result); err != nil {
				fmt.Println(err)
				continue rePrompt
			}
		}

		return result
	}
}

// Ensure non-empty strings.
func NonemptyValidator(input string) error {
	if len(input) == 0 {
		return errors.New("input is blank, please try again")
	}
	return nil
}

// Very simple email validation to prevent obvious mistakes.
func EmailValidator(email string) error {
	if len(email) >= 4 && strings.Contains(email, "@") && strings.Contains(email, ".") {
		return nil
	}
	return errors.New("invalid email: must be at least 4 characters and contain '@' and '.'")
}

func RegexValidator(text string) error {
	if _, err := regexp.Compile(text); err != nil {
		return fmt.Errorf("invalid regex: %v", err)
	}
	return nil
}

func DateValidator(text string) error {
	if len(text) == 0 { // allow no date
		return nil
	}
	if _, err := time.Parse("2006-01-02", text); err != nil {
		return fmt.Errorf("invalid date: %v", err)
	}
	return nil
}
