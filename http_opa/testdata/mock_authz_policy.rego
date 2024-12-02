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
				".": [
					"custom-admin-role",
					"administrator-role"
				],
				"compartment-40-red.": [
					"devops-role",
					"secops-role"
				]
			},
			"user-group-40": {
				".": [
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
				".": [
					"custom-admin-role",
					"administrator-role"
				],
				"compartment-16-red.": [
					"devops-role",
					"secops-role"
				]
			},
			"user-group-16": {
				".": [
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
				".": [
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
				".": [
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
ROOT_COMPARTMENT_ID := "."

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

filter_compartment_permissions_api = filtered_perm_arr {
	count(trim_space(merged_input.compartment_id)) > 0
	merged_input.compartment_id != ROOT_COMPARTMENT_ID
	filtered_perm_arr := ["filtered-perm-a", "filtered-perm-b"]
} else = filtered_perm_arr {
	filtered_perm_arr := input.permissions
}

filter_compartment_features_api = filtered_feat_map {
	count(trim_space(merged_input.compartment_id)) > 0
	merged_input.compartment_id != ROOT_COMPARTMENT_ID
	filtered_feat_map := {
		"filtered-app-a": ["filtered-app-a-feat-a", "filtered-app-a-feat-b"],
		"filtered-app-b":  ["filtered-app-b-feat-a"],
	}
} else = filtered_feat_map {
	filtered_feat_map := input.application_features
}

filter_compartment_permissions_test_fn(cpt_id, perm_arr, exp_set) {
	got_set := filter_compartment_permissions_api with input as {
		"compartment_id": cpt_id,
		"permissions": perm_arr,
	}
	trace(sprintf("got_set: %v", [got_set]))
	trace(sprintf("exp_set: %v", [exp_set]))
	got_set == exp_set
}

filter_compartment_features_test_fn(cpt_id, app_feat_map, exp_map) {
	got_map := filter_compartment_features_api with input as {
		"compartment_id": cpt_id,
		"application_features": app_feat_map,
	}
	trace(sprintf("got_map: %v", [got_map]))
	trace(sprintf("exp_map: %v", [exp_map]))
	got_map == exp_map
}

test_filter_compartment_api {
	filter_compartment_permissions_test_fn("",
		["user-view", "tag-read"],
		["user-view", "tag-read"])

	filter_compartment_permissions_test_fn(".",
		["user-view", "tag-read"],
		["user-view", "tag-read"])

	filter_compartment_permissions_test_fn("green.",
		["user-view", "tag-read"],
		["filtered-perm-a", "filtered-perm-b"])

	filter_compartment_features_test_fn("",
		{"ddi": ["dhcp", "ipam"], "ui": ["anycast"]},
		{"ddi": ["dhcp", "ipam"], "ui": ["anycast"]})

	filter_compartment_features_test_fn(".",
		{"ddi": ["dhcp", "ipam"], "ui": ["anycast"]},
		{"ddi": ["dhcp", "ipam"], "ui": ["anycast"]})

	filter_compartment_features_test_fn("green.",
		{"ddi": ["dhcp", "ipam"], "ui": ["anycast"]},
		{"filtered-app-a": ["filtered-app-a-feat-a", "filtered-app-a-feat-b"],
		 "filtered-app-b": ["filtered-app-b-feat-a"]})
}

# opa test -v mock_authz_policy.rego
# opa run --server mock_authz_policy.rego
# curl -X GET  -H 'Content-Type: application/json' http://localhost:8181/v1/data/authz/rbac/acct_entitlements_api | jq .
# curl -X POST -H 'Content-Type: application/json' http://localhost:8181/v1/data/authz/rbac/acct_entitlements_api | jq .

