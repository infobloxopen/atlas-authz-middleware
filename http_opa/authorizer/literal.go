package authorizer

// ABACKey is a context.Context key type
type ABACKey string
type ObligationKey string

const (
	// DefaultValidatePath is default OPA path to perform authz validation
	DefaultValidatePath = "v1/data/authz/rbac/validate_v1"

	REDACTED = "redacted"
	TypeKey  = ABACKey("ABACType")
	VerbKey  = ABACKey("ABACVerb")
	ObKey    = ObligationKey("obligations")

	DefaultAcctEntitlementsApiPath = "v1/data/authz/rbac/acct_entitlements_api"
)
