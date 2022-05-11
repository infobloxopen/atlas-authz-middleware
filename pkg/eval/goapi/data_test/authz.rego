package authz.rbac

import data.authz.endpoint_features
import data.authz.features
import data.authz.group_criteria
import data.authz.group_roles
import data.authz.permission_endpoints
import data.authz.role_permissions

#ABAC
#SHOULD NOT BE REMOVED! ABAC policy rego will be inserted by opa-operator
#ABAC

# TODO measure performance of table based virtual doc approach
# TODO partial evaluation should improve performance of virtual docs https://blog.openpolicyagent.org/partial-evaluation-162750eaf422
# string attribute - non empty intersection criterion
resolved_groups[[account, grp_name]] {
	some account, grp_name
	my_criteria := group_criteria[account][grp_name]
	possible_values := my_criteria[attr_name]
	attr_val := merged_input[attr_name]
	is_string(attr_val)
	attr_val == possible_values[_]
}

# array attribute - non empty intersection criterion
resolved_groups[[account, grp_name]] {
	some account, grp_name
	my_criteria := group_criteria[account][grp_name]
	possible_values := my_criteria[attr_name]
	attr_values := merged_input[attr_name]
	is_array(attr_values)
	attr_values[_] == possible_values[_]
}

# default group correspond to criteria: None from PARGs
resolved_groups[[account, grp_name]] {
	some account, grp_name
	my_criteria := group_criteria[account][grp_name]
	is_null(my_criteria)
}

# virtual document in form of table mapping account, resource group and subject group to permitted endpoints by RBAC
permitted_endpoints[[grpAccount, roleAccount, res_group, sub_group, endpoint]] {
	some grpAccount, roleAccount
	resource_groups := group_roles[grpAccount]
	subject_groups := resource_groups[res_group]
	roles := subject_groups[sub_group]
	perms := role_permissions[roleAccount][roles[_]]
	endpoint := permission_endpoints[perms[_]][_]
}

# single underscore string "_" key represents OPA data derived from global PARGs in authz namespace
# double underscore string "__" key represents OPA data derived from application specific PARGs
default getAccounts = ["_", "__"]

getAccounts = accounts {
	accounts = [merged_input.account_id, "_", "__"]
}

default rbac = false

rbac {
	grpAccounts := getAccounts

	# groups from request + groups resolved by group criteria
	some res_group, sub_group
	resolved_groups[[grpAccounts[_], res_group]]
	resolved_groups[[grpAccounts[_], sub_group]]
	permitted_endpoints[[grpAccounts[_], getAccounts[_], res_group, sub_group, input.endpoint]]
}

# virtual document in form of table mapping account and group to licensed endpoints

# global data
licensed_endpoints[[account, app, endpoint]] {
	some account, app, endpoint
	account == "_"
	apps := features[account]
	feature := apps[app][_]
	feature == endpoint_features[endpoint][_]
}

# account data
licensed_endpoints[[account, app, endpoint]] {
	some account, app, endpoint
	account != "_"
	apps := features.account[account]
	feature := apps[app][_]
	feature == endpoint_features[endpoint][_]
}

default entitlement = false

default interservice = false

interservice {
	merged_input.service == "all"
	merged_input.aud == "ib-stk"
}

entitlement {
	interservice
}

entitlement {
	# single underscore string "_" key means global
	accounts := getAccounts
	licensed_endpoints[[accounts[_], merged_input.application, merged_input.endpoint]]
}

has_token {
	is_string(input.jwt)
	count(trim_space(input.jwt)) > 0
}

default endpoint = ""

endpoint = input.endpoint

default application = ""

application = input.application

print_details(rbac_check, entitlement_check) {
	x := "undefined"

	application := object.get(input, "application", x)
	endpoint := object.get(input, "endpoint", x)
	full_method := object.get(input, "full_method", x)
	request_id := object.get(input, "request_id", x)
	entitled_services := object.get(input, "entitled_services", x)

	account_id := object.get(merged_input, "account_id", x)
	service := object.get(merged_input, "service", x)
	aud := object.get(merged_input, "aud", x)
	groups := object.get(merged_input, "groups", x)
	# ATLAS-12416: comment out print() until we can force sidecar-opa version upgrade
	#	print("authz-rbac-details:", json.marshal({
	#		"application": application,
	#		"endpoint": endpoint,
	#		"full_method": full_method,
	#		"request_id": request_id,
	#		"entitled_services": entitled_services,
	#		"jwt": {
	#			"account_id": account_id,
	#			"service": service,
	#			"aud": aud,
	#			"groups": groups,
	#		},
	#		"rbac_check": rbac_check,
	#		"entitlement_check": entitlement_check,
	#	}))
}

resource = res {
	parts := split(input.resource, ".")
	count(parts) == 5
	parts[0] == "blox0"
	res = {
		"domain": parts[1],
		"type": parts[2],
		"realm": parts[3],
		"id": parts[4],
	}
}

else = res {
	res := {
		"domain": "",
		"type": "",
		"realm": "",
		"id": "",
	}
}

merged_input = merged {
	has_token
	[_, payload, _] := io.jwt.decode(input.jwt)
	merged := object.union(payload, {"application": application, "endpoint": endpoint})
}

else = input {
	merged := input
}

deny[msg] {
	not entitlement
	msg := sprintf("entitlement check failed - application: %s, endpoint: %s, account: %v", [application, endpoint, getAccounts])
}

deny[msg] {
	not rbac
	msg := sprintf("RBAC check failed - application: %s, endpoint: %s, account: %v", [application, endpoint, getAccounts])
}

default allow = false

allow {
	rbac_check := rbac
	entitlement_check := entitlement
	print_details(rbac_check, entitlement_check)
	rbac_check
	entitlement_check
}

validate_v1[key] = val {
	is_string(input.request_id)
	key := "request_id"
	val := input.request_id
}

validate_v1[key] = val {
	key := "allow"
	val := allow
}

validate_v1[key] = val {
	key := "obligations"
	val := obligations
}

# Add per-account entitled_features, only if requested
validate_v1[key] = val {
	is_array(input.entitled_services)
	count(input.entitled_services) > 0
	key := "entitled_features"
	val := entitled_features
}

# Add per-account entitled_features, only if requested
entitled_features[entitled_svc_name] = entitled_svc_feats {
	is_array(input.entitled_services)
	count(input.entitled_services) > 0
	entitled_svc_name := input.entitled_services[_]
	entitled_svc_feats := features.account[merged_input.account_id][entitled_svc_name]
}

# Public api for querying account-entitlements
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
	acct_ent_result := features.account
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
		ent_svc_feats := features.account[acct_id][ent_svc_name]
	}
}

# Get all acct_entitlements for specific acct_entitlements_acct_ids
acct_entitlements_filtered_api[acct_id] = acct_ent {
	is_array(input.acct_entitlements_acct_ids)
	count(input.acct_entitlements_acct_ids) > 0
	acct_entitlements_services_is_empty
	acct_id := input.acct_entitlements_acct_ids[_]
	acct_ent := features.account[acct_id]
}

# Get acct_entitlements for all account_ids but specific acct_entitlements_services
# (Requires new 'in' keyword only supported in OPA 0.34.0 and later)
acct_entitlements_filtered_api[acct_id] = acct_ent {
	acct_entitlements_acct_ids_is_empty
	is_array(input.acct_entitlements_services)
	count(input.acct_entitlements_services) > 0

	#	some acct_id, _ in features.account
	#	acct_ent := {ent_svc_name: ent_svc_feats |
	#		ent_svc_name := input.acct_entitlements_services[_]
	#		ent_svc_feats := features.account[acct_id][ent_svc_name]
	#	}
	acct_id := "not-implemented-yet"
	acct_ent := {}
}

obligations[policy] = oblige {
	false
	policy := "this obligation never added since it's false"
	oblige := {}
}

obligations[policy] = oblige {
	rbac
	policy := "authz.rbac.rbac"
	oblige := {}
}

obligations[policy] = oblige {
	entitlement
	policy := "authz.rbac.entitlement"
	oblige := {}
}
