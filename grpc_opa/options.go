package grpc_opa_middleware

import (
	"net/http"

	"github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"
)

type Option func(c *Config)

// WithAddress
func WithAddress(address string) Option {
	return func(c *Config) {
		c.address = address
	}
}

// WithHTTPClient overrides the http.Client used to call Opa
func WithHTTPClient(client *http.Client) Option {
	return func(c *Config) {
		if client != nil {
			c.httpCli = client
		}
	}
}

// WithOpaClienter overrides the Clienter used to call Opa.
// This option takes precedence over WithHTTPClient.
func WithOpaClienter(clienter opa_client.Clienter) Option {
	return func(c *Config) {
		if clienter != nil {
			c.clienter = clienter
		}
	}
}

// WithOpaEvaluator overrides the OpaEvaluator use to
// evaluate authorization against OPA.
func WithOpaEvaluator(opaEvaluator OpaEvaluator) Option {
	return func(c *Config) {
		c.opaEvaluator = opaEvaluator
	}
}

// WithAuthorizer overrides the request/response
// processing of OPA. Multiple authorizers can be passed
func WithAuthorizer(auther ...Authorizer) Option {
	return func(c *Config) {
		c.authorizer = auther
	}
}

// WithDecisionInputHandler supplies optional DecisionInputHandler
// for DefaultAuthorizer to obtain additional input for OPA
// ABAC decision processing.
func WithDecisionInputHandler(decisionHandler DecisionInputHandler) Option {
	return func(c *Config) {
		c.decisionInputHandler = decisionHandler
	}
}

// WithClaimsVerifier overrides default ClaimsVerifier
func WithClaimsVerifier(claimsVerifier ClaimsVerifier) Option {
	return func(c *Config) {
		c.claimsVerifier = claimsVerifier
	}
}

// WithEntitledServices overrides default EntitledServices
func WithEntitledServices(entitledServices ...string) Option {
	return func(c *Config) {
		c.entitledServices = entitledServices
	}
}

// WithAcctEntitlementsApiPath overrides default AcctEntitlementsApiPath
func WithAcctEntitlementsApiPath(acctEntitlementsApi string) Option {
	return func(c *Config) {
		c.acctEntitlementsApi = acctEntitlementsApi
	}
}

// WithFilterComparmentPermissionsApiPath overrides default CurrentUserCompartmentsApiPath
func WithFilterComparmentPermissionsApiPath(filterCompartmentPermsApi string) Option {
	return func(c *Config) {
		c.filterCompartmentPermsApi = filterCompartmentPermsApi
	}
}

// WithFilterComparmentFeaturesApiPath overrides default CurrentUserCompartmentsApiPath
func WithFilterComparmentFeaturesApiPath(filterCompartmentFeatsApi string) Option {
	return func(c *Config) {
		c.filterCompartmentFeatsApi = filterCompartmentFeatsApi
	}
}

// WithAccountMetadataApiPath overrides default AccountMetadataApiPath
func WithAccountMetadataApiPath(accountMetadataApi string) Option {
	return func(c *Config) {
		c.accountMetadataApi = accountMetadataApi
	}
}

// WithParentCspIdApiPath overrides default ParentCspIdApiPath
func WithParentCspIdApiPath(parentCspIdApi string) Option {
	return func(c *Config) {
		c.parentCspIdApi = parentCspIdApi
	}
}

// WithCspBySfdcApiPath overrides default CspBySfdcApiPath
func WithCspBySfdcApiPath(cspBySfdcApi string) Option {
	return func(c *Config) {
		c.cspBySfdcApi = cspBySfdcApi
	}
}

// WithSandboxesForParentApiPath overrides default SandboxesForParentApiPath
func WithSandboxesForParentApiPath(sandboxesForParentApi string) Option {
	return func(c *Config) {
		c.sandboxesForParentApi = sandboxesForParentApi
	}
}

// WithAcctEntitlementsFilteredApiPath overrides the default path for
// acct_entitlements_filtered_api (used by GetAccountDetails and GetEnrichedAccountMetadata).
func WithAcctEntitlementsFilteredApiPath(path string) Option {
	return func(c *Config) {
		if path != "" {
			c.acctEntitlementsFilteredApi = path
		}
	}
}

// WithAccountMetadataBySfdcApiPath overrides the default path for
// get_account_metadata_by_sfdc_api (used by GetAccountDetailsBySfdc).
func WithAccountMetadataBySfdcApiPath(path string) Option {
	return func(c *Config) {
		if path != "" {
			c.accountMetadataBySfdcApi = path
		}
	}
}

