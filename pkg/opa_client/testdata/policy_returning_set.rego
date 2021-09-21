# Sample Rego used to verify that Rego sets are returned as json arrays by OPA REST API.
# See unit-test test_get_results, which verifies Rego set is returned.

package policy_returning_set

row_arr := [ `e`, `a`, `d`, `b`, `c`, ]

row_set[item] {
	item := row_arr[_]
}

get_results = {
	"allow": true,
	"row_set": row_set,
}

test_get_results {
	results := get_results
	trace(sprintf("results: %v", [results]))
	row_arr == [ `e`, `a`, `d`, `b`, `c`, ]
	results.row_set == { `d`, `c`, `a`, `b`, `e`, }
	results.row_set != [ `e`, `a`, `d`, `b`, `c`, ]
}

# opa test -v policy_returning_set.rego
# opa run --server policy_returning_set.rego
# curl -X GET  -H 'Content-Type: application/json' http://localhost:8181/v1/data/policy_returning_set/get_results | jq .
# curl -X POST -H 'Content-Type: application/json' http://localhost:8181/v1/data/policy_returning_set/get_results | jq .

