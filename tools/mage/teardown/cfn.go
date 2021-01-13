package teardown

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
	"fmt"
	"time"

	"github.com/panther-labs/panther/pkg/awscfn"
	"github.com/panther-labs/panther/tools/cfnstacks"
	"github.com/panther-labs/panther/tools/mage/clients"
)

const pollInterval = 5 * time.Second

// Destroy all Panther CloudFormation stacks
func DestroyCfnStacks(masterStack string) error {
	if masterStack != "" {
		log.Infof("deleting master stack '%s'", masterStack)
		return awscfn.DeleteStack(clients.Cfn(), log, masterStack, pollInterval)
	}

	type deleteStackResult struct {
		stackName string
		err       error
	}

	// Define a common routine for processing stack delete results
	var errCount, finishCount int
	handleResult := func(result deleteStackResult) {
		finishCount++
		if result.err != nil {
			log.Errorf("    - %s failed to delete (%d/%d): %v",
				result.stackName, finishCount, cfnstacks.NumStacks, result.err)
			errCount++
			return
		}

		log.Infof("    √ %s deleted (%d/%d)", result.stackName, finishCount, cfnstacks.NumStacks)
	}

	deleteFunc := func(stack string, r chan deleteStackResult) {
		r <- deleteStackResult{stackName: stack, err: awscfn.DeleteStack(clients.Cfn(), log, stack, pollInterval)}
	}

	log.Infof("deleting %d CloudFormation stacks", cfnstacks.NumStacks)

	// Delete stacks which don't have downstream dependencies: web, onboard, appsync, dashboard
	results := make(chan deleteStackResult)
	for _, stack := range []string{cfnstacks.Frontend, cfnstacks.Onboard, cfnstacks.Appsync, cfnstacks.Dashboard} {
		go deleteFunc(stack, results)
	}
	for i := 0; i < 4; i++ {
		handleResult(<-results)
	}

	// Next, delete cloud-security and log-analysis
	for _, stack := range []string{cfnstacks.Cloudsec, cfnstacks.LogAnalysis} {
		go deleteFunc(stack, results)
	}
	for i := 0; i < 2; i++ {
		handleResult(<-results)
	}

	// Finally, in order (sequentially): core, bootstrap-gateway, bootstrap
	for _, stack := range []string{cfnstacks.Core, cfnstacks.Gateway, cfnstacks.Bootstrap} {
		go deleteFunc(stack, results)
		handleResult(<-results)
	}

	if errCount > 0 {
		return fmt.Errorf("%d stack(s) failed to delete", errCount)
	}
	return nil
}
