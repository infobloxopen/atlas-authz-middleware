package utils_test

type TestingTContextKeyType string
const TestingTContextKey = TestingTContextKeyType("*testing.T")

func NullClaimsVerifier([]string, []string) (string, []error) {
	return "", nil
}
