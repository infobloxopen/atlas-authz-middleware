package opautil

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/infobloxopen/atlas-authz-middleware/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// ErrInvalidObligations is returned upon invalid obligations
	ErrInvalidObligations = status.Errorf(codes.Internal, "Invalid obligations")
)

// ObligationsEnum enumerates the different kinds of ObligationsNode
type ObligationsEnum int

// The different kinds of ObligationsNode
const (
	ObligationsEmpty ObligationsEnum = iota // Default "zero" value for uninitialized ObligationsEnum
	ObligationsCondition
	ObligationsAnd
	ObligationsOr
)

// String implements fmt.Stringer interface
func (o8e ObligationsEnum) String() string {
	return []string{
		"ObligationsEmpty",
		"ObligationsCondition",
		"ObligationsAnd",
		"ObligationsOr",
	}[o8e]
}

// ObligationsNode defines the generic obligations tree returned by middleware in the context
type ObligationsNode struct {
	Kind      ObligationsEnum
	Tag       string
	Condition string
	Children  []*ObligationsNode
}

// String() returns a multiline pretty string representation (actually JSON),
// intended to be human-readable for debugging purposes.
func (o8n *ObligationsNode) String() string {
	jsonBytes, err := json.MarshalIndent(o8n, "", "  ")
	if err != nil {
		return "cannot json.MarshalIndent"
	}
	return string(jsonBytes)
}

// ShallowLength returns the length of this node.
// It does not include the lengths of any nested nodes.
// Length zero means this node is empty (has no obligation).
func (o8n *ObligationsNode) ShallowLength() int {
	if o8n == nil {
		return 0
	}

	switch o8n.Kind {
	case ObligationsAnd, ObligationsOr:
		if o8n.Children == nil {
			return 0
		}
		return len(o8n.Children)
	case ObligationsCondition:
		return 1
	}

	return 0
}

// IsShallowEmpty returns whether this node is empty (has no obligations).
func (o8n *ObligationsNode) IsShallowEmpty() bool {
	return o8n.ShallowLength() == 0
}

// ShallowLessThan returns true if lhs less than rhs.
// Does not consider nested nodes.
// Intended for use by DeepSort method.
func (lhs *ObligationsNode) ShallowLessThan(rhs *ObligationsNode) bool {
	if lhs == nil && rhs == nil {
		return false
	} else if lhs == nil {
		return true
	}

	if lhs.Kind != rhs.Kind {
		return lhs.Kind < rhs.Kind
	}

	if lhs.Tag != rhs.Tag {
		return lhs.Tag < rhs.Tag
	}

	if lhs.Condition != rhs.Condition {
		return lhs.Condition < rhs.Condition
	}

	if lhs.Children == nil && rhs.Children == nil {
		return false
	} else if lhs.Children == nil {
		return true
	}

	if len(lhs.Children) != len(rhs.Children) {
		return len(lhs.Children) < len(rhs.Children)
	}

	return false
}

// DeepSort recursively sorts any nested nodes.
// Intended to be used in unit-tests to force
// deterministic order for comparison.
func (o8n *ObligationsNode) DeepSort() {
	if o8n == nil || o8n.Children == nil {
		return
	}

	for i := range o8n.Children {
		o8n.Children[i].DeepSort()
	}

	sort.SliceStable(o8n.Children, func(i, j int) bool {
		return o8n.Children[i].ShallowLessThan(o8n.Children[j])
	})

	return
}

// parseOPAObligations parses the obligations returned from OPA
// and returns them in standard format.
func ParseOPAObligations(opaObligations interface{}) (*ObligationsNode, error) {
	if opaObligations == nil {
		return nil, nil
	}

	arrIfc, isArr := opaObligations.([]interface{})
	mapIfc, isMap := opaObligations.(map[string]interface{})

	if isArr {
		return parseObligationsArray(arrIfc)
	} else if isMap {
		return parseObligationsMap(mapIfc)
	}

	return nil, ErrInvalidObligations
}

// obligations json.Unmarshal()'d as type:
// []interface {}{[]interface {}{"ctx.metric == \"dhcp\""}}
func parseObligationsArray(arrIfc []interface{}) (*ObligationsNode, error) {
	if common.IsNilInterface(arrIfc) {
		return nil, nil
	}

	result := &ObligationsNode{
		Kind: ObligationsEmpty,
	}

	for _, subIfc := range arrIfc {
		if common.IsNilInterface(subIfc) {
			continue
		}

		subResult := &ObligationsNode{
			Kind: ObligationsEmpty,
		}

		subArrIfc, ok := subIfc.([]interface{})
		if !ok {
			return nil, ErrInvalidObligations
		}

		for _, itemIfc := range subArrIfc {
			s, ok := itemIfc.(string)
			if !ok {
				return nil, ErrInvalidObligations
			}

			leafNode := &ObligationsNode{
				Kind:      ObligationsCondition,
				Condition: s,
			}

			if subResult.Children == nil {
				subResult.Kind = ObligationsOr
				subResult.Children = []*ObligationsNode{}
			}
			subResult.Children = append(subResult.Children, leafNode)
		}

		if subResult.ShallowLength() > 0 {
			if result.Children == nil {
				result.Kind = ObligationsOr
				result.Children = []*ObligationsNode{}
			}
			result.Children = append(result.Children, subResult)
		}
	}

	return result, nil
}

// obligations json.Unmarshal()'d as type:
// map[string]interface {}{"policy1_guid":map[string]interface {}{"stmt0":[]interface {}{"ctx.metric == \"dhcp\""}}}
func parseObligationsMap(mapIfc map[string]interface{}) (*ObligationsNode, error) {
	if common.IsNilInterface(mapIfc) {
		return nil, nil
	}

	rootNode := &ObligationsNode{
		Kind: ObligationsEmpty,
	}

	for policyName, subIfc := range mapIfc {
		if common.IsNilInterface(subIfc) {
			continue
		}

		if !strings.HasPrefix(policyName, "abac.") {
			continue
		}

		stmtMapIfc, ok := subIfc.(map[string]interface{})
		if !ok {
			return nil, ErrInvalidObligations
		}

		policyNode := &ObligationsNode{
			Kind: ObligationsEmpty,
			Tag:  policyName,
		}

		for stmtName, stmtIfc := range stmtMapIfc {
			subArrIfc, ok := stmtIfc.([]interface{})
			if !ok {
				return nil, ErrInvalidObligations
			}

			stmtNode := &ObligationsNode{
				Kind: ObligationsEmpty,
				Tag:  stmtName,
			}

			for _, itemIfc := range subArrIfc {
				s, ok := itemIfc.(string)
				if !ok {
					return nil, ErrInvalidObligations
				}

				leafNode := &ObligationsNode{
					Kind:      ObligationsCondition,
					Condition: s,
				}

				if stmtNode.Children == nil {
					stmtNode.Kind = ObligationsOr
					stmtNode.Children = []*ObligationsNode{}
				}
				stmtNode.Children = append(stmtNode.Children, leafNode)
			}

			if stmtNode.ShallowLength() > 0 {
				if policyNode.Children == nil {
					policyNode.Kind = ObligationsOr
					policyNode.Children = []*ObligationsNode{}
				}
				policyNode.Children = append(policyNode.Children, stmtNode)
			}
		}

		if policyNode.ShallowLength() > 0 {
			if rootNode.Children == nil {
				rootNode.Kind = ObligationsOr
				rootNode.Children = []*ObligationsNode{}
			}
			rootNode.Children = append(rootNode.Children, policyNode)
		}
	}

	return rootNode, nil
}
