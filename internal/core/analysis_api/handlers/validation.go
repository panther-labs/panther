package handlers

import (
  "github.com/panther-labs/panther/internal/core/analysis_api/analysis"
  "github.com/panther-labs/panther/internal/core/logtypesapi"
  "github.com/panther-labs/panther/pkg/awsretry"
  "github.com/panther-labs/panther/pkg/gatewayapi"
)

var (
  lambdaLogTypesClient *lambda.Lambda
  logtypesAPI          *logtypesapi.LogTypesAPILambdaClient

  logtypeSetMap map[string]struct{}
)


// Traverse a passed set of resource and return an error if any of them are not found in the current
// list of valid resource types
//
// CAVEAT: This method uses a hardcoded list of existing resource types. If this method is returning
// unexpected errors the hardcoded list is up to date.
func ValidResourceTypeSet(checkResourceTypeSet []string) error {
	for _, writeResourceTypeEntry := range checkResourceTypeSet {
		if _, exists := resourceTypesProvider.ResourceTypes[writeResourceTypeEntry]; !exists {
			// Found a resource type that doesnt exist
			return errors.Errorf("%s", writeResourceTypeEntry)
		}
	}
	return nil
}

// Request the logtypes-api for the current set of logtypes and assign the result list to 'logtypeSetMap'
func refreshLogTypes() {
	// Temporary get log types for testing
	logtypes, err := logtypesAPI.ListAvailableLogTypes(context.Background())
	if err != nil {
		return
	}

	logtypeSetMap = make(map[string]interface{})
	for _, logtype := range logtypes.LogTypes {
		logtypeSetMap[logtype] = nil
	}
}

// Return the existence of the passed logtype in the current logtypes.
// NOTE: Accuret results require an updated logtypeSetMap - currently accomplished using the call to
// 'refreshLogTypes'. That method makes a call to the log-types api, so use it as infrequently as possible
// The refresh method can be called a single time for multiple individual log type validation checks.
func logtypeIsValid(logtype string) (found bool) {
	_, found = logtypeSetMap[logtype]
	return
}

// Traverse a passed set of resource and return an error if any of them are not found in the current
// list of valid resource types
//
// CAVEAT: This method will trigger a request to the log-types api EVERY time it is called.
func validateLogtypeSet(logtypes []string) (err error) {
	refreshLogTypes()
	for _, logtype := range logtypes {
		if !logtypeIsValid(logtype) {
			return errors.Errorf("%s", logtype)
		}
	}
	return
}
