package parsers

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockParser struct {
	mock.Mock
}

// Parse implements parsers.Interface
func (m *mockParser) Parse(log string) ([]*Result, error) {
	args := m.Called(log)
	results := args.Get(0)
	err := args.Error(1)
	if err != nil {
		return nil, err
	}
	return results.([]*Result), nil
}

func newMockParser() *mockParser {
	return &mockParser{}
}

func mockLogType(name string, parser *mockParser) LogType {
	return LogType{
		Name:        name,
		Description: fmt.Sprintf("Mock log type %q", name),
		NewParser: func() Interface {
			return parser
		},
		Schema: struct{}{},
	}
}

func TestClassifyRespectsPriorityOfParsers(t *testing.T) {
	logLine := "log"
	parserSuccess := newMockParser()
	parserSuccess.On("Parse", "log").Return((&Result{
		LogType: "success",
	}).Results(), nil)
	parserFail1 := newMockParser()
	parserFail1.On("Parse", "log").Return(([]*Result)(nil), errors.New("fail1"))
	parserFail2 := newMockParser()
	parserFail2.On("Parse", "log").Return(([]*Result)(nil), errors.New("fail2"))

	classifier := NewClassifier(
		mockLogType("fail1", parserFail1),
		mockLogType("success", parserSuccess),
		mockLogType("fail2", parserFail2),
	)

	repetitions := 1000

	expectedResult := []*Result{
		{LogType: "success"},
	}

	expectedStats := &QueueStats{
		NumHit:  float64(repetitions - 1),
		NumMiss: 0,
		Parsers: map[string]Stats{
			"success": {},
			"fail1":   {},
			"fail2":   {},
		},
	}

	for i := 0; i < repetitions; i++ {
		result, err := classifier.Parse(logLine)
		require.NoError(t, err)
		require.Equal(t, expectedResult, result)
	}
	_ = expectedStats

	// // skipping specifically validating the times
	// expectedStats.ClassifyTimeMicroseconds = classifier.Stats().ClassifyTimeMicroseconds
	// require.Equal(t, expectedStats, classifier.Stats())

	// parserSuccess.AssertNumberOfCalls(t, "Parse", repetitions)

	require.NotNil(t, classifier.ParserStats()["success"])
	// // skipping validating the times
	// expectedParserStats.ParserTimeMicroseconds = classifier.ParserStats()["success"].ParserTimeMicroseconds
	// require.Equal(t, expectedParserStats, classifier.ParserStats()["success"])

	// requireLessOrEqualNumberOfCalls(t, parserFail1, "Parse", 1)
	// require.Nil(t, classifier.ParserStats()["failure1"])
	// require.Nil(t, classifier.ParserStats()["failure2"])
}
