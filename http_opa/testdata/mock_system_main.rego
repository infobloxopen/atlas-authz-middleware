# OPA POST query without url path will query OPA's configured default decision document.
# By default the default decision document is /data/system/main.
# ( See https://www.openpolicyagent.org/docs/v0.29.4/rest-api/#query-api )
#
# This test rego defines a dummy authz policy for /data/system/main.
# It verifies that queries with and without url path:
# - requires different input document formats
# - returns different response document formats
#
# $ opa run --server mock_system_main.rego
#
# POST query WITHOUT url path against unspecified default decision document
# Notice that:
# - the input document must NOT be encapsulated inside "input"
# - the return document is NOT encapsulated inside "result"
# $ curl -X POST -H 'Content-Type: application/json' http://localhost:8181/ -d '{"application": "automobile", "endpoint": "Vehicle.StompGasPedal"}' | jq .
#   ==> returns {"allow": true}
# $ curl -X POST -H 'Content-Type: application/json' http://localhost:8181/ -d '{"input": {"application": "automobile", "endpoint": "Vehicle.StompGasPedal"}}' | jq .
#   ==> returns {"allow": false}
#
# POST query WITH url path against any explicitly specified decision document
# Notice that:
# - the input document MUST be encapsulated inside "input"
# - the return document is ALWAYS encapsulated inside "result"
# $ curl -X POST -H 'Content-Type: application/json' http://localhost:8181/v1/data/system/main -d '{"application": "automobile", "endpoint": "Vehicle.StompGasPedal"}' | jq .
#   ==> returns {"result": {"allow": false}}
# $ curl -X POST -H 'Content-Type: application/json' http://localhost:8181/v1/data/system/main -d '{"input": {"application": "automobile", "endpoint": "Vehicle.StompGasPedal"}}' | jq .
#   ==> returns {"result": {"allow": true}}
#

package system

default allow = false

allow {
	input.application == "automobile"
	input.endpoint == "Vehicle.StompGasPedal"
}

main = {
	"allow": allow,
}
