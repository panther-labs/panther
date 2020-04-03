package api

import (
	"github.com/panther-labs/panther/pkg/genericapi"
)

// conform to generic api
func apiError(err error) error {
		err = &genericapi.InternalError{Message: err.Error()}
	return err
}
