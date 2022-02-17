package custom_query_test

map_map_arr := {
	"2001016": {
		"laptop": [
			"lenovo",
		],
		"hardware": [
			"hdd4tb",
			"ram32mb",
		],
		"software": [
			"msoffice",
			"visualstudio",
		],
	},
	"2001040": {
		"laptop": [
			"apple",
		],
		"hardware": [
			"ram64mb",
			"ssd1tb",
		],
		"software": [
			"msoffice",
			"photoshop",
		],
	},
}

test_map_map_arr {
	results := map_map_arr
	trace(sprintf("results: %v", [results]))
}

# opa test -v custom_query_test.rego
# opa run --server custom_query_test.rego
# curl -X GET  -H 'Content-Type: application/json' http://localhost:8181/v1/data/custom_query_test/map_map_arr | jq .
# curl -X POST -H 'Content-Type: application/json' http://localhost:8181/v1/data/custom_query_test/map_map_arr | jq .

