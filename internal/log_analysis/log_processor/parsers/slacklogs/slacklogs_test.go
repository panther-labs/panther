package slacklogs

import (
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes/logtesting"
	"testing"
)

func TestDuoParsers(t *testing.T) {
	logtesting.RunTestsFromYAML(t, LogTypes(), "./testdata/slacklogs_test.yml")
}