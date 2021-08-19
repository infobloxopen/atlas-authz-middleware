package grpc_opa_middleware

import (
	"strings"

	"github.com/infobloxopen/seal/pkg/compiler/sql"
)

// ToSQLPredicate recursively converts obligations node tree into SQL predicate
func (o8n *ObligationsNode) ToSQLPredicate(sqlc *sqlcompiler.SQLCompiler) (string, error) {
	if o8n.Kind == ObligationsCondition {
		singleSQL, err := sqlc.CompileCondition(o8n.Condition)
		if err != nil {
			return "", err
		}
		return AddOuterParens(singleSQL), nil
	} else if (o8n.Kind != ObligationsAnd) && (o8n.Kind != ObligationsOr) {
		return "", ErrInvalidObligations
	}

	if len(o8n.Children) <= 0 {
		return "", ErrInvalidObligations
	}

	childSQLArr := make([]string, 0, len(o8n.Children))
	for _, childNode := range o8n.Children {
		if childNode.Kind == ObligationsEmpty {
			continue
		}

		childSQL, err := childNode.ToSQLPredicate(sqlc)
		if err != nil {
			return "", err
		}

		childSQLArr = append(childSQLArr, AddOuterParens(childSQL))
	}

	joinStr := " OR "
	if o8n.Kind == ObligationsAnd {
		joinStr = " AND "
	}

	outerParens := false
	if len(childSQLArr) > 1 {
		outerParens = true
	}

	var resultSQL strings.Builder
	if outerParens {
		resultSQL.WriteString("(")
	}
	resultSQL.WriteString(strings.Join(childSQLArr, joinStr))
	if outerParens {
		resultSQL.WriteString(")")
	}

	return resultSQL.String(), nil
}

// AddOuterParens adds outer parentheses only if required
func AddOuterParens(sqlStr string) string {
	if sqlStr[0] == '(' && sqlStr[len(sqlStr)-1] == ')' {
		return sqlStr
	}

	var resultSQL strings.Builder
	resultSQL.WriteString("(")
	resultSQL.WriteString(sqlStr)
	resultSQL.WriteString(")")
	return resultSQL.String()
}
