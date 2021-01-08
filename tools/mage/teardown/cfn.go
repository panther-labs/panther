package teardown

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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

	// Trigger the deletion of the main stacks in parallel
	//
	// The bootstrap stacks have to be last because of the ECS cluster and custom resource Lambda.
	parallelStacks := []string{
		cfnstacks.Appsync,
		cfnstacks.Cloudsec,
		cfnstacks.Core,
		cfnstacks.Dashboard,
		cfnstacks.Frontend,
		cfnstacks.LogAnalysis,
		cfnstacks.Onboard,
	}
	log.Infof("deleting %d CloudFormation stacks", cfnstacks.NumStacks)

	deleteFunc := func(stack string, r chan deleteStackResult) {
		r <- deleteStackResult{stackName: stack, err: awscfn.DeleteStack(clients.Cfn(), log, stack, pollInterval)}
	}

	results := make(chan deleteStackResult)
	for _, stack := range parallelStacks {
		go deleteFunc(stack, results)
	}

	// Wait for all of the main stacks to finish deleting
	for i := 0; i < len(parallelStacks); i++ {
		handleResult(<-results)
	}

	// Now finish with the bootstrap stacks
	// bootstrap-gateway must be deleted first because it will empty the ECR repo
	go deleteFunc(cfnstacks.Gateway, results)
	handleResult(<-results)
	go deleteFunc(cfnstacks.Bootstrap, results)
	handleResult(<-results)

	if errCount > 0 {
		return fmt.Errorf("%d stack(s) failed to delete", errCount)
	}
	return nil
}
