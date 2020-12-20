package awslogs

import (
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes/logtesting"
	"testing"
)

func TestVPCDns(t *testing.T) {
	logtesting.RunTestsFromYAML(t, LogTypes(), "./testdata/vpc_dns_tests.yml")
}

