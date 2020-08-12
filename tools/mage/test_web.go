package mage

var webTests = []testTask{
	{"npm run test", testWebIntegration},
	{"npm run eslint", testWebEslint},
	{"npm run tsc", testWebTsc},
}

// Test and lint web source
func (Test) Web() {
	runTests(webTests)
}

func testWebEslint() error {
	return runWithCapturedOutput("npm", "run", "eslint")
}

func testWebTsc() error {
	return runWithCapturedOutput("npm", "run", "tsc")
}

func testWebIntegration() error {
	return runWithCapturedOutput("npm", "run", "test")
}
