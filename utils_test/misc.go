package utils_test

type TestingTContextKeyType string
const TestingTContextKey = TestingTContextKeyType("*testing.T")

type TestCaseIndexContextKeyType string
const TestCaseIndexContextKey = TestCaseIndexContextKeyType("TestCaseIndex")

type TestCaseNameContextKeyType string
const TestCaseNameContextKey = TestCaseNameContextKeyType("TestCaseName")

func NullClaimsVerifier([]string, []string) (string, []error) {
	return "", nil
}
