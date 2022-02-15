package authz.rbac

validate_v1 = {
	"allow": true,
}

acct_entitlements_api = acct_ent_result {
	acct_ent_result := account_service_features
}

account_service_features := {
	"2001016": {
		"environment": [
			"ac",
			"heated-seats",
		],
		"wheel": [
			"abs",
			"alloy",
			"tpms",
		],
	},
	"2001040": {
		"environment": [
			"ac",
			"side-mirror-defogger",
		],
		"powertrain": [
			"automatic",
			"turbo",
		],
	},
}

test_acct_entitlements_api {
	results := acct_entitlements_api
	trace(sprintf("results: %v", [results]))
	results == account_service_features
}

# opa test -v mock_authz_policy.rego
# opa run --server mock_authz_policy.rego
# curl -X GET  -H 'Content-Type: application/json' http://localhost:8181/v1/data/authz/rbac/acct_entitlements_api | jq .
# curl -X POST -H 'Content-Type: application/json' http://localhost:8181/v1/data/authz/rbac/acct_entitlements_api | jq .

