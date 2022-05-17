package utils_test

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/sirupsen/logrus"

	"github.com/infobloxopen/atlas-app-toolkit/requestid"
)

type ctxValues struct {
	withLogger bool
	requestID  string
	// JWT claims
	accountID  string
	idtyAcctID string
	idtyUserID string
	groups     []string
	aud        string
	service    string
	expiresAt  int64
	// entitlements
	entitlsKey interface{}
	entitls    []string
}

type CtxValue func(*ctxValues)

func WithLogger(yes bool) CtxValue {
	return func(vals *ctxValues) {
		vals.withLogger = true
	}
}

func WithRequestID(requestID string) CtxValue {
	return func(vals *ctxValues) {
		vals.requestID = requestID
	}
}

func WithJWTAccountID(ID string) CtxValue {
	return func(vals *ctxValues) {
		vals.accountID = ID
	}
}

func WithJWTIdentityAccountID(ID string) CtxValue {
	return func(vals *ctxValues) {
		vals.idtyAcctID = ID
	}
}

func WithJWTIdentityUserID(ID string) CtxValue {
	return func(vals *ctxValues) {
		vals.idtyUserID = ID
	}
}

func WithJWTGroups(groups ...string) CtxValue {
	return func(vals *ctxValues) {
		vals.groups = groups
	}
}

func WithJWTAudience(aud string) CtxValue {
	return func(vals *ctxValues) {
		vals.aud = aud
	}
}

func WithJWTService(svc string) CtxValue {
	return func(vals *ctxValues) {
		vals.service = svc
	}
}

func WithEntitledFeatures(key interface{}, features ...string) CtxValue {
	return func(vals *ctxValues) {
		vals.entitlsKey = key
		vals.entitls = features
	}
}

func WithExpirationDate(at time.Time) CtxValue {
	return func(vals *ctxValues) {
		vals.expiresAt = at.Unix()
	}
}

func BuildCtx(log *logrus.Logger, ctxVals ...CtxValue) context.Context {
	var (
		ctx  = context.Background()
		vals = new(ctxValues)
	)

	for _, val := range ctxVals {
		val(vals)
	}

	// logger
	if vals.withLogger {
		ctx = ctxlogrus.ToContext(ctx, logrus.NewEntry(log))
	}

	// request ID
	ctx = requestid.NewContext(ctx, vals.requestID)

	//set claims
	claims := make(jwt.MapClaims)
	claims["account_id"] = vals.accountID
	claims["groups"] = vals.groups
	claims["identity_account_id"] = vals.idtyAcctID
	claims["identity_user_id"] = vals.idtyUserID
	claims["aud"] = vals.aud
	claims["service"] = vals.service
	claims["exp"] = vals.expiresAt

	ctx = NewContextWithJWTClaims(log, ctx, claims)

	// entitled features
	if vals.entitlsKey != nil && vals.entitlsKey != "" {
		l := fmt.Sprintf("entitls: %v -> ", vals.entitls)
		defer func() {
			log.Debug(l)
		}()

		m := map[string]interface{}{}
		for _, e := range vals.entitls {
			l += " | "
			switch sf := strings.Split(e, "."); len(sf) {
			case 0:
				l += "nil map"
				m = nil
			case 1:
				l += fmt.Sprintf("%s:nil (no features)", m[sf[0]])
				m[sf[0]] = nil
			case 2: // valid entitled_features
				l += fmt.Sprintf("%s:%s", m[sf[0]], m[sf[1]])
				if _, found := m[sf[0]]; !found {
					m[sf[0]] = []interface{}{}
				}
				m[sf[0]] = append(m[sf[0]].([]interface{}), sf[1])
			default:
				l += "nil map (wrong test input)"
				m = nil
			}
		}

		ctx = context.WithValue(ctx, vals.entitlsKey, m)
	}

	return ctx
}
