package authz.rbac

has_token {
	is_string(input.jwt)
	count(trim_space(input.jwt)) > 0
}

merged_input = payload {
	has_token
	[_, payload, _] := io.jwt.decode(input.jwt)
}

else = payload {
	payload := input
}

validate_v1 = {
	"allow": true,
}

acct_entitlements_acct_ids_is_empty {
	not input.acct_entitlements_acct_ids
}

acct_entitlements_acct_ids_is_empty {
	is_array(input.acct_entitlements_acct_ids)
	count(input.acct_entitlements_acct_ids) == 0
}

acct_entitlements_services_is_empty {
	not input.acct_entitlements_services
}

acct_entitlements_services_is_empty {
	is_array(input.acct_entitlements_services)
	count(input.acct_entitlements_services) == 0
}

acct_entitlements_api = acct_ent_result {
	# No filtering, get all acct_entitlements for all acct_entitlements_acct_ids
	acct_entitlements_acct_ids_is_empty
	acct_entitlements_services_is_empty
	acct_ent_result := account_service_features
} else = acct_ent_result {
	acct_ent_result := acct_entitlements_filtered_api
}

# Get acct_entitlements by specific acct_entitlements_acct_ids
# and specific acct_entitlements_services
acct_entitlements_filtered_api[acct_id] = acct_ent {
	is_array(input.acct_entitlements_acct_ids)
	count(input.acct_entitlements_acct_ids) > 0
	is_array(input.acct_entitlements_services)
	count(input.acct_entitlements_services) > 0
	acct_id := input.acct_entitlements_acct_ids[_]
	acct_ent := {ent_svc_name: ent_svc_feats |
		ent_svc_name := input.acct_entitlements_services[_]
		ent_svc_feats := account_service_features[acct_id][ent_svc_name]
	}
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
	"2001230": {
		"powertrain": [
			"manual",
			"v8",
		],
		"wheel": [
			"run-flat",
		],
	},
}

test_acct_entitlements_api_no_input {
	results := acct_entitlements_api
	trace(sprintf("results: %v", [results]))
	results == account_service_features
}

test_acct_entitlements_api_empty_input {
	results := acct_entitlements_api with input as {
		"acct_entitlements_acct_ids": [],
		"acct_entitlements_services": [],
	}
	trace(sprintf("results: %v", [results]))
	results == account_service_features
}

test_acct_entitlements_api_with_input {
	results := acct_entitlements_api with input as {
		"acct_entitlements_acct_ids": ["2001040", "2001230"],
		"acct_entitlements_services": ["powertrain", "wheel"],
	}
	trace(sprintf("results: %v", [results]))
	results == {
		"2001040": {
			"powertrain": [
				"automatic",
				"turbo",
			],
		},
		"2001230": {
			"powertrain": [
				"manual",
				"v8",
			],
			"wheel": [
				"run-flat",
			],
		},
	}
}

group_compartment_roles := {
	"40": {
		"all-resources": {
			"custom-admin-group": {
				"root-compartment": [
					"custom-admin-role",
					"administrator-role"
				],
				"compartment-40-red.": [
					"devops-role",
					"secops-role"
				]
			},
			"user-group-40": {
				"root-compartment": [
					"custom-admin-role",
					"administrator-role"
				],
				"compartment-40-red.": [
					"devops-role",
					"secops-role"
				]
			},
			"user": {
				"compartment-40-green.": [
					"readonly-role"
				]
			}
		}
	},
	"16": {
		"all-resources": {
			"custom-admin-group-16": {
				"root-compartment": [
					"custom-admin-role",
					"administrator-role"
				],
				"compartment-16-red.": [
					"devops-role",
					"secops-role"
				]
			},
			"user-group-16": {
				"root-compartment": [
					"custom-admin-role",
					"administrator-role"
				],
				"compartment-16-red.": [
					"devops-role",
					"secops-role"
				]
			},
			"user": {
				"compartment-16-green.": [
					"readonly-role"
				]
			}
		}
	},
	"3101": {
		"all-resources": {
			"devops-group": {
				"root-compartment": [
					"widget-role-read"
				],
				"red.": [
					"widget-role-create",
					"gadget-role-create"
				],
				"green.": [
					"widget-role-update"
				],
				"green.car.": [
					"gizmo-role-create"
				]
			},
			"secops-group": {
				"root-compartment": [
					"gadget-role-read",
					"gadget-role-list"
				],
				"green.": [
					"gadget-role-update"
				],
				"green.car.": [
					"gizmo-role-update"
				],
				"green.boat.": [
					"gizmo-role-delete"
				],
				"green.car.wheel.": [
					"gizmo-role-read"
				],
				"green.boat.anchor.": [
					"gizmo-role-list"
				],
				"blue.": [
					"widget-role-delete",
					"gadget-role-delete"
				]
			}
		}
	}
}

# Well-known hardcoded root-compartment id used throughout AuthZ/Identity code
ROOT_COMPARTMENT_ID := "root-compartment"

current_user_compartments[compartment] {
	compartment != ROOT_COMPARTMENT_ID
	group_compartment_roles[merged_input.account_id][_][merged_input.groups[_]][compartment]
}

current_user_compartments_test_fn(acct_id, groups, exp_set) {
	got_set := current_user_compartments with input as {
		"account_id": acct_id,
		"groups": groups,
	}
	trace(sprintf("got_set: %v", [got_set]))
	trace(sprintf("exp_set: %v", [exp_set]))
	got_set == exp_set
}

test_current_user_compartments {
	current_user_compartments_test_fn("40", ["custom-admin-group", "user-group-40"],
		{"compartment-40-red."})
	current_user_compartments_test_fn("40", ["custom-admin-group", "user"],
		{"compartment-40-red.", "compartment-40-green."})
}

# opa test -v mock_authz_policy.rego
# opa run --server mock_authz_policy.rego
# curl -X GET  -H 'Content-Type: application/json' http://localhost:8181/v1/data/authz/rbac/acct_entitlements_api | jq .
# curl -X POST -H 'Content-Type: application/json' http://localhost:8181/v1/data/authz/rbac/acct_entitlements_api | jq .

