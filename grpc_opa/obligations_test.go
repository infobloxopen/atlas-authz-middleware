package grpc_opa_middleware

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func Test_parseOPAObligations(t *testing.T) {
	for idx, tst := range obligationsNodeTests {
		var resp OPAResponse

		err := json.Unmarshal([]byte(tst.regoRespJSON), &resp)
		if err != nil {
			t.Errorf("tst#%d: err=%s trying to json.Unmarshal: %s",
				idx, err, tst.regoRespJSON)
			continue
		}

		t.Logf("tst#%d: resp=%#v", idx, resp)
		if _, ok := resp[string(ObKey)]; !ok {
			if strings.Contains(tst.regoRespJSON, `"obligations":`) {
				t.Errorf("tst#%d: '%s' key not found in OPAResponse",
					idx, string(ObKey))
			}
			continue
		}
		actualVal, actualErr := parseOPAObligations(resp[string(ObKey)])

		if actualErr != tst.expectedErr {
			t.Errorf("tst#%d: expectedErr=%s actualErr=%s",
				idx, tst.expectedErr, actualErr)
		}

		if actualVal != nil {
			t.Logf("tst#%d: before DeepSort: %s", idx, actualVal)
			actualVal.DeepSort()
		}
		if !reflect.DeepEqual(actualVal, tst.expectedVal) {
			t.Errorf("tst#%d: expectedVal=%s\nactualVal=%s",
				idx, tst.expectedVal, actualVal)
		}
	}
}

var obligationsNodeTests = []struct {
	expectedErr  error
	regoRespJSON string
	expectedVal  *ObligationsNode
}{
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true
		}`,
		expectedVal:  nil,
	},
	{
		expectedErr:  ErrInvalidObligations,
		regoRespJSON: `{
			"allow": true,
			"obligations": "bad obligations value"
		}`,
		expectedVal:  nil,
	},
	{
		expectedErr:  ErrInvalidObligations,
		regoRespJSON: `{
			"allow": true,
			"obligations": [ "bad obligations value" ]
		}`,
		expectedVal:  nil,
	},
	{
		expectedErr:  ErrInvalidObligations,
		regoRespJSON: `{
			"allow": true,
			"obligations": [ [ 3.14 ] ]
		}`,
		expectedVal:  nil,
	},
	{
		expectedErr:  ErrInvalidObligations,
		regoRespJSON: `{
			"allow": true,
			"obligations": { "policy1_guid": "bad obligations value" }
		}`,
		expectedVal:  nil,
	},
	{
		expectedErr:  ErrInvalidObligations,
		regoRespJSON: `{
			"allow": true,
			"obligations": { "bad_obligations_value": [ 3.14 ]}
		}`,
		expectedVal:  nil,
	},
	{
		expectedErr:  ErrInvalidObligations,
		regoRespJSON: `{
			"allow": true,
			"obligations": { "policy1_guid": { "stmt0": "bad obligations value" }}
		}`,
		expectedVal:  nil,
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": []
		}`,
		expectedVal:  &ObligationsNode{},
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": [ [], [] ]
		}`,
		expectedVal:  &ObligationsNode{},
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": [ [], [ "a" ] ]
		}`,
		expectedVal:  &ObligationsNode{
			Kind: ObligationsOr,
			Children: []*ObligationsNode{
				&ObligationsNode{
					Kind: ObligationsOr,
					Children: []*ObligationsNode{
						&ObligationsNode{
							Kind: ObligationsCondition,
							Condition: "a",
						},
					},
				},
			},
		},
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": [ [ "a", "b" ], [ "c" ] ]
		}`,
		expectedVal:  &ObligationsNode{
			Kind: ObligationsOr,
			Children: []*ObligationsNode{
				&ObligationsNode{
					Kind: ObligationsOr,
					Children: []*ObligationsNode{
						&ObligationsNode{
							Kind: ObligationsCondition,
							Condition: "c",
						},
					},
				},
				&ObligationsNode{
					Kind: ObligationsOr,
					Children: []*ObligationsNode{
						&ObligationsNode{
							Kind: ObligationsCondition,
							Condition: "a",
						},
						&ObligationsNode{
							Kind: ObligationsCondition,
							Condition: "b",
						},
					},
				},
			},
		},
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": {}
		}`,
		expectedVal:  &ObligationsNode{},
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": {
				"policy1_guid": {},
				"policy2_guid": {}
			}
		}`,
		expectedVal:  &ObligationsNode{},
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": {
				"policy1_guid": {},
				"policy2_guid": {
					"stmt1": []
				}
			}
		}`,
		expectedVal:  &ObligationsNode{},
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": {
				"policy1_guid": {
					"stmt0": []
				},
				"policy2_guid": {
					"stmt1": []
				}
			}
		}`,
		expectedVal:  &ObligationsNode{},
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": {
				"policy1_guid": {
					"stmt0": [ "i", "j" ]
				},
				"policy2_guid": {}
			}
		}`,
		expectedVal:  &ObligationsNode{
			Kind: ObligationsOr,
			Children: []*ObligationsNode{
				&ObligationsNode{
					Kind: ObligationsOr,
					Tag: "policy1_guid",
					Children: []*ObligationsNode{
						&ObligationsNode{
							Kind: ObligationsOr,
							Tag: "stmt0",
							Children: []*ObligationsNode{
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "i",
								},
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "j",
								},
							},
						},
					},
				},
			},
		},
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": {
				"policy1_guid": {
					"stmt0": [ "i", "j", "k" ]
				},
				"policy2_guid": {
					"stmt1": []
				}
			}
		}`,
		expectedVal:  &ObligationsNode{
			Kind: ObligationsOr,
			Children: []*ObligationsNode{
				&ObligationsNode{
					Kind: ObligationsOr,
					Tag: "policy1_guid",
					Children: []*ObligationsNode{
						&ObligationsNode{
							Kind: ObligationsOr,
							Tag: "stmt0",
							Children: []*ObligationsNode{
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "i",
								},
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "j",
								},
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "k",
								},
							},
						},
					},
				},
			},
		},
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": {
				"policy1_guid": {
					"stmt0": [ "a" ]
				},
				"policy2_guid": {
					"stmt0": [ "b", "c" ],
					"stmt1": [ "d" ]
				}
			}
		}`,
		expectedVal:  &ObligationsNode{
			Kind: ObligationsOr,
			Children: []*ObligationsNode{
				&ObligationsNode{
					Kind: ObligationsOr,
					Tag: "policy1_guid",
					Children: []*ObligationsNode{
						&ObligationsNode{
							Kind: ObligationsOr,
							Tag: "stmt0",
							Children: []*ObligationsNode{
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "a",
								},
							},
						},
					},
				},
				&ObligationsNode{
					Kind: ObligationsOr,
					Tag: "policy2_guid",
					Children: []*ObligationsNode{
						&ObligationsNode{
							Kind: ObligationsOr,
							Tag: "stmt0",
							Children: []*ObligationsNode{
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "b",
								},
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "c",
								},
							},
						},
						&ObligationsNode{
							Kind: ObligationsOr,
							Tag: "stmt1",
							Children: []*ObligationsNode{
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "d",
								},
							},
						},
					},
				},
			},
		},
	},
}
