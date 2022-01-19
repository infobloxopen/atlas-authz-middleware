package grpc_opa_middleware

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/infobloxopen/seal/pkg/compiler/sql"
)

func Test_parseOPAObligations(t *testing.T) {
	for idx, tst := range obligationsNodeTests {
		var resp OPAResponse

		err := json.Unmarshal([]byte(tst.regoRespJSON), &resp)
		if err != nil {
			t.Errorf("tst#%d: FAIL: err=%s trying to json.Unmarshal: %s",
				idx, err, tst.regoRespJSON)
			continue
		}

		t.Logf("tst#%d: resp=%#v", idx, resp)
		if _, ok := resp[string(ObKey)]; !ok {
			if strings.Contains(tst.regoRespJSON, `"obligations":`) {
				t.Errorf("tst#%d: FAIL: '%s' key not found in OPAResponse",
					idx, string(ObKey))
			}
			continue
		}
		actualVal, actualErr := parseOPAObligations(resp[string(ObKey)])

		if actualErr != tst.expectedErr {
			t.Errorf("tst#%d: FAIL: expectedErr=%s actualErr=%s",
				idx, tst.expectedErr, actualErr)
		}

		if actualVal != nil {
			t.Logf("tst#%d: before DeepSort: %s", idx, actualVal)
			actualVal.DeepSort()
		}
		if !reflect.DeepEqual(actualVal, tst.expectedVal) {
			t.Errorf("tst#%d: FAIL: expectedVal=%s\nactualVal=%s",
				idx, tst.expectedVal, actualVal)
		}

		if actualVal == nil || actualVal.IsShallowEmpty() {
			continue
		}

		sqlc := sqlcompiler.NewSQLCompiler().WithDialect(sqlcompiler.DialectPostgres).
			WithTypeMapper(sqlcompiler.NewTypeMapper("ddi.*").ToSQLTable("*").
				WithPropertyMapper(sqlcompiler.NewPropertyMapper("*").ToSQLColumn("*")),
			)
		actualSQL, sqlErr := actualVal.ToSQLPredicate(sqlc)
		t.Logf("tst#%d: sqlErr: %s", idx, sqlErr)
		t.Logf("tst#%d: actualSQL: `%s`", idx, actualSQL)

		if sqlErr != nil && !tst.expectSQLErr {
			t.Errorf("tst#%d: FAIL: Got unexpected ToSQLPredicate err: %s", idx, sqlErr)
		} else if sqlErr == nil && tst.expectSQLErr {
			t.Errorf("tst#%d: FAIL: Expected ToSQLPredicate err, but got nil err", idx)
		}

		if actualSQL != tst.expectedSQL {
			t.Errorf("tst#%d: FAIL: Expected SQL: `%s`\nBut got SQL: `%s`", idx,
				tst.expectedSQL, actualSQL)
		}
	}
}

var obligationsNodeTests = []struct {
	expectedErr  error
	regoRespJSON string
	expectedVal  *ObligationsNode
	expectSQLErr bool
	expectedSQL  string
}{
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true
		}`,
		expectedVal:  nil,
		expectSQLErr: false,
		expectedSQL:  ``,
	},
	{
		expectedErr:  ErrInvalidObligations,
		regoRespJSON: `{
			"allow": true,
			"obligations": "bad obligations value"
		}`,
		expectedVal:  nil,
		expectSQLErr: false,
		expectedSQL:  ``,
	},
	{
		expectedErr:  ErrInvalidObligations,
		regoRespJSON: `{
			"allow": true,
			"obligations": [ "bad obligations value" ]
		}`,
		expectedVal:  nil,
		expectSQLErr: false,
		expectedSQL:  ``,
	},
	{
		expectedErr:  ErrInvalidObligations,
		regoRespJSON: `{
			"allow": true,
			"obligations": [ [ 3.14 ] ]
		}`,
		expectedVal:  nil,
		expectSQLErr: false,
		expectedSQL:  ``,
	},
	{
		expectedErr:  ErrInvalidObligations,
		regoRespJSON: `{
			"allow": true,
			"obligations": { "abac.policy1_guid": "bad obligations value" }
		}`,
		expectedVal:  nil,
		expectSQLErr: false,
		expectedSQL:  ``,
	},
	{
		expectedErr:  ErrInvalidObligations,
		regoRespJSON: `{
			"allow": true,
			"obligations": { "abac.bad_obligations_value": [ 3.14 ]}
		}`,
		expectedVal:  nil,
		expectSQLErr: false,
		expectedSQL:  ``,
	},
	{
		expectedErr:  ErrInvalidObligations,
		regoRespJSON: `{
			"allow": true,
			"obligations": { "abac.policy1_guid": { "stmt0": "bad obligations value" }}
		}`,
		expectedVal:  nil,
		expectSQLErr: false,
		expectedSQL:  ``,
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": []
		}`,
		expectedVal:  &ObligationsNode{},
		expectSQLErr: false,
		expectedSQL:  ``,
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": [ [], null, [] ]
		}`,
		expectedVal:  &ObligationsNode{},
		expectSQLErr: false,
		expectedSQL:  ``,
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": [ [], [ "type:ddi.ipam; not ctx.a =~ 1" ] ]
		}`,
		expectedVal:  &ObligationsNode{
			Kind: ObligationsOr,
			Children: []*ObligationsNode{
				&ObligationsNode{
					Kind: ObligationsOr,
					Children: []*ObligationsNode{
						&ObligationsNode{
							Kind: ObligationsCondition,
							Condition: "type:ddi.ipam; not ctx.a =~ 1",
						},
					},
				},
			},
		},
		expectSQLErr: false,
		expectedSQL:  `(NOT (ipam.a ~ 1))`,
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": [ [ "ctx.a <= 1", "ctx.b != 2" ], [ "ctx.c >= 3" ] ]
		}`,
		expectedVal:  &ObligationsNode{
			Kind: ObligationsOr,
			Children: []*ObligationsNode{
				&ObligationsNode{
					Kind: ObligationsOr,
					Children: []*ObligationsNode{
						&ObligationsNode{
							Kind: ObligationsCondition,
							Condition: "ctx.c >= 3",
						},
					},
				},
				&ObligationsNode{
					Kind: ObligationsOr,
					Children: []*ObligationsNode{
						&ObligationsNode{
							Kind: ObligationsCondition,
							Condition: "ctx.a <= 1",
						},
						&ObligationsNode{
							Kind: ObligationsCondition,
							Condition: "ctx.b != 2",
						},
					},
				},
			},
		},
		expectSQLErr: false,
		expectedSQL:  `((ctx.c >= 3) OR ((ctx.a <= 1) OR (ctx.b != 2)))`,
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": {}
		}`,
		expectedVal:  &ObligationsNode{},
		expectSQLErr: false,
		expectedSQL:  ``,
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": {
				"abac.policy1_guid": {},
				"abac.policy2_guid": null,
				"abac.policy3_guid": {}
			}
		}`,
		expectedVal:  &ObligationsNode{},
		expectSQLErr: false,
		expectedSQL:  ``,
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": {
				"abac.policy1_guid": {},
				"abac.policy2_guid": {
					"stmt1": []
				}
			}
		}`,
		expectedVal:  &ObligationsNode{},
		expectSQLErr: false,
		expectedSQL:  ``,
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": {
				"abac.policy1_guid": {
					"stmt0": []
				},
				"abac.policy2_guid": {
					"stmt1": []
				}
			}
		}`,
		expectedVal:  &ObligationsNode{},
		expectSQLErr: false,
		expectedSQL:  ``,
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": {
				"abac.policy1_guid": {
					"stmt0": [ "type:ddi.ipam; ctx.i < 1", "type:ddi.ipam; ctx.j > 2" ]
				},
				"abac.policy2_guid": {}
			}
		}`,
		expectedVal:  &ObligationsNode{
			Kind: ObligationsOr,
			Children: []*ObligationsNode{
				&ObligationsNode{
					Kind: ObligationsOr,
					Tag: "abac.policy1_guid",
					Children: []*ObligationsNode{
						&ObligationsNode{
							Kind: ObligationsOr,
							Tag: "stmt0",
							Children: []*ObligationsNode{
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "type:ddi.ipam; ctx.i < 1",
								},
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "type:ddi.ipam; ctx.j > 2",
								},
							},
						},
					},
				},
			},
		},
		expectSQLErr: false,
		expectedSQL:  `((ipam.i < 1) OR (ipam.j > 2))`,
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": {
				"abac.policy1_guid": {
					"stmt0": [ "ctx.i == 1", "ctx.j == 2", "ctx.k == 3" ]
				},
				"abac.policy2_guid": {
					"stmt1": []
				}
			}
		}`,
		expectedVal:  &ObligationsNode{
			Kind: ObligationsOr,
			Children: []*ObligationsNode{
				&ObligationsNode{
					Kind: ObligationsOr,
					Tag: "abac.policy1_guid",
					Children: []*ObligationsNode{
						&ObligationsNode{
							Kind: ObligationsOr,
							Tag: "stmt0",
							Children: []*ObligationsNode{
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "ctx.i == 1",
								},
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "ctx.j == 2",
								},
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "ctx.k == 3",
								},
							},
						},
					},
				},
			},
		},
		expectSQLErr: false,
		expectedSQL:  `((ctx.i = 1) OR (ctx.j = 2) OR (ctx.k = 3))`,
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": {
				"abac.policy1_guid": {
					"stmt0": [ "ctx.a == 1" ]
				},
				"abac.policy2_guid": {
					"stmt0": [ "ctx.b == 2", "ctx.c == 3" ],
					"stmt1": [ "ctx.d == 4" ]
				}
			}
		}`,
		expectedVal:  &ObligationsNode{
			Kind: ObligationsOr,
			Children: []*ObligationsNode{
				&ObligationsNode{
					Kind: ObligationsOr,
					Tag: "abac.policy1_guid",
					Children: []*ObligationsNode{
						&ObligationsNode{
							Kind: ObligationsOr,
							Tag: "stmt0",
							Children: []*ObligationsNode{
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "ctx.a == 1",
								},
							},
						},
					},
				},
				&ObligationsNode{
					Kind: ObligationsOr,
					Tag: "abac.policy2_guid",
					Children: []*ObligationsNode{
						&ObligationsNode{
							Kind: ObligationsOr,
							Tag: "stmt0",
							Children: []*ObligationsNode{
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "ctx.b == 2",
								},
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "ctx.c == 3",
								},
							},
						},
						&ObligationsNode{
							Kind: ObligationsOr,
							Tag: "stmt1",
							Children: []*ObligationsNode{
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "ctx.d == 4",
								},
							},
						},
					},
				},
			},
		},
		expectSQLErr: false,
		expectedSQL:  `((ctx.a = 1) OR (((ctx.b = 2) OR (ctx.c = 3)) OR (ctx.d = 4)))`,
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": {
				"abac.policy1_guid": {
					"stmt0": [ "type:ddi.ipam; ctx.tags[\"a\"] == 1" ]
				}
			}
		}`,
		expectedVal:  &ObligationsNode{
			Kind: ObligationsOr,
			Children: []*ObligationsNode{
				&ObligationsNode{
					Kind: ObligationsOr,
					Tag: "abac.policy1_guid",
					Children: []*ObligationsNode{
						&ObligationsNode{
							Kind: ObligationsOr,
							Tag: "stmt0",
							Children: []*ObligationsNode{
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "type:ddi.ipam; ctx.tags[\"a\"] == 1",
								},
							},
						},
					},
				},
			},
		},
		expectSQLErr: false,
		expectedSQL:  `(ipam.tags->'a' = 1)`,
	},
	{
		expectedErr:  nil,
		regoRespJSON: `{
			"allow": true,
			"obligations": {
				"abac.policy1_guid": {
					"stmt0": [ "ctx.a in 1, 2, 3" ]
				}
			}
		}`,
		expectedVal:  &ObligationsNode{
			Kind: ObligationsOr,
			Children: []*ObligationsNode{
				&ObligationsNode{
					Kind: ObligationsOr,
					Tag: "abac.policy1_guid",
					Children: []*ObligationsNode{
						&ObligationsNode{
							Kind: ObligationsOr,
							Tag: "stmt0",
							Children: []*ObligationsNode{
								&ObligationsNode{
									Kind: ObligationsCondition,
									Condition: "ctx.a in 1, 2, 3",
								},
							},
						},
					},
				},
			},
		},
		expectSQLErr: true, // TODO: SQL for IN operator not supported yet
		expectedSQL:  ``,   // `(ctx.a IN (1, 2, 3))`,
	},
}
