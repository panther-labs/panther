package mage

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
	"strings"

	"github.com/panther-labs/panther/pkg/prompt"
	"github.com/panther-labs/panther/tools/cfnstacks"
	"github.com/panther-labs/panther/tools/mage/clients"
	"github.com/panther-labs/panther/tools/mage/teardown"
)

// Teardown Destroy all Panther infrastructure
func Teardown() {
	masterStack := teardownConfirmation()
	if err := teardown.DestroyCfnStacks(masterStack); err != nil {
		log.Fatal(err)
	}

	// CloudFormation will not delete any Panther S3 buckets (DeletionPolicy: Retain), we do so here.
	if err := teardown.DestroyPantherBuckets(clients.S3()); err != nil {
		log.Fatal(err)
	}

	log.Info("successfully removed Panther infrastructure")
}

func teardownConfirmation() string {
	// When deploying from source ('mage deploy'), there will be several top-level stacks.
	// When deploying the master template, there is only one main stack whose name we do not know.
	stack := os.Getenv("STACK")
	if stack == "" {
		log.Warnf("No STACK env variable found; assuming you have %d top-level stacks from 'mage deploy'",
			cfnstacks.NumStacks)
	}

	template := "Teardown will destroy all Panther infra in account %s (%s)"
	args := []interface{}{clients.AccountID(), clients.Region()}
	if stack != "" {
		template += " with master stack '%s'"
		args = append(args, stack)
	}

	log.Warnf(template, args...)
	result := prompt.Read("Are you sure you want to continue? (yes|no) ", prompt.NonemptyValidator)
	if strings.ToLower(result) != "yes" {
		log.Fatal("teardown aborted")
	}

	return stack
}
