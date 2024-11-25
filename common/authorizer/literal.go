package authorizer

// ABACKey is a context.Context key type
type ABACKey string
type ObligationKey string

const (
	// DefaultValidatePath is default OPA path to perform authz validation
	DefaultValidatePath = "v1/data/authz/rbac/validate_v1"

	// DefaultAcctEntitlementsApiPath is default OPA path to fetch acct entitlements
	DefaultAcctEntitlementsApiPath = "v1/data/authz/rbac/acct_entitlements_api"

	// DefaultCurrentUserCompartmentsPath is default OPA path to fetch current user's compartments
	DefaultCurrentUserCompartmentsPath = "v1/data/authz/rbac/current_user_compartments"

	// DefaultFilterCompartmentPermissionsApiPath is default OPA path to filter compartment permissions
	DefaultFilterCompartmentPermissionsApiPath = "v1/data/authz/rbac/filter_compartment_permissions_api"

	// DefaultFilterCompartmentFeaturesApiPath is default OPA path to filter compartment features
	DefaultFilterCompartmentFeaturesApiPath = "v1/data/authz/rbac/filter_compartment_features_api"

	REDACTED = "redacted"
	TypeKey  = ABACKey("ABACType")
	VerbKey  = ABACKey("ABACVerb")
	ObKey    = ObligationKey("obligations")
)
