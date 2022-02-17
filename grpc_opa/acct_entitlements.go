package grpc_opa_middleware

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	logrus "github.com/sirupsen/logrus"

	"github.com/infobloxopen/atlas-authz-middleware/pkg/json_utils"
)

const (
	// DefaultAcctEntitlementsApiPath is default OPA path to fetch acct entitlements
	DefaultAcctEntitlementsApiPath = "v1/data/authz/rbac/acct_entitlements_api"
)

// AcctEntitlementsType is a convenience data type, returned by GetAcctEntitlements()
// (map of acct_id to map of service to array of features)
type AcctEntitlementsType map[string]map[string][]string

// AcctEntitlementsApiResult is the data type returned by OPA RESTAPI query to acct_entitlements_api
type AcctEntitlementsApiResult struct {
	Loggr  *logrus.Logger        `json:"-"`
	Result *AcctEntitlementsType `json:"result"`
}

// UnmarshalJSON implements json.Unmarshaler interface for AcctEntitlementsApiResult
func (u *AcctEntitlementsApiResult) UnmarshalJSON(rawBytes []byte) error {
	if u.Loggr != nil {
		u.Loggr.Tracef("AcctEntitlementsApiResult.UnmarshalJSON: u=%#v", u)
		u.Loggr.Tracef("AcctEntitlementsApiResult.UnmarshalJSON: '%s'", string(rawBytes))
	}

	jdec := json_utils.NewJsonDecoder(strings.NewReader(string(rawBytes)),
		//json_utils.WithLogger(u.Loggr),
	)

	if _, err := jdec.ExpectDelim("{"); err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}

	result := "result"
	if _, err := jdec.ExpectString(&result); err != nil {
		return err
	}

	delimStr, err := jdec.ExpectDelim("{", json_utils.WithAllowNull(true))
	if err != nil {
		return err
	}
	if delimStr == nil {
		return nil
	}

	u.Result = &AcctEntitlementsType{}

	for jdec.Decoder().More() {
		acct, err := jdec.ExpectString(nil)
		if err != nil {
			return err
		}

		delimStr, err = jdec.ExpectDelim("{", json_utils.WithAllowNull(true))
		if err != nil {
			return err
		}
		if delimStr == nil {
			continue
		}

		(*u.Result)[*acct] = map[string][]string{}

		for jdec.Decoder().More() {
			svc, err := jdec.ExpectString(nil)
			if err != nil {
				return err
			}

			delimStr, err = jdec.ExpectDelim("[", json_utils.WithAllowNull(true))
			if err != nil {
				return err
			}
			if delimStr == nil {
				continue
			}

			(*u.Result)[*acct][*svc] = []string{}

			for jdec.Decoder().More() {
				feat, err := jdec.ExpectString(nil)
				if err != nil {
					return err
				}
				(*u.Result)[*acct][*svc] = append((*u.Result)[*acct][*svc], *feat)
			}

			if _, err := jdec.ExpectDelim("]"); err != nil {
				return err
			}
		}

		if _, err := jdec.ExpectDelim("}"); err != nil {
			return err
		}
	}

	if _, err := jdec.ExpectDelim("}"); err != nil {
		return err
	}

	if _, err := jdec.ExpectDelim("}"); err != nil {
		return err
	}

	if u.Loggr != nil {
		u.Loggr.Tracef("AcctEntitlementsApiResult.UnmarshalJSON: u=%#v", u)
	}
	return nil
}

// GetAcctEntitlementsBytes queries account entitled features data
// and returns the raw JSON string response
func (a *DefaultAuthorizer) GetAcctEntitlementsBytes(ctx context.Context) ([]byte, error) {
	lgNtry := ctxlogrus.Extract(ctx)

	rawBytes, err := a.clienter.CustomQueryBytes(ctx, a.acctEntitlementsApi, nil)
	if err != nil {
		lgNtry.WithError(err).Error("get_acct_entitlements_raw_fail")
		return nil, err
	}

	lgNtry.WithFields(logrus.Fields{
		"rawBytes": string(rawBytes),
	}).Trace("get_acct_entitlements_raw_okay")

	return rawBytes, nil
}

// GetAcctEntitlements queries account entitled features data
func (a *DefaultAuthorizer) GetAcctEntitlements(ctx context.Context) (*AcctEntitlementsType, error) {
	lgNtry := ctxlogrus.Extract(ctx)
	acctResult := AcctEntitlementsApiResult{Loggr: lgNtry.Logger}

	err := a.clienter.CustomQuery(ctx, a.acctEntitlementsApi, nil, &acctResult)
	if err != nil {
		lgNtry.WithError(err).Error("get_acct_entitlements_fail")
		return nil, err
	}

	lgNtry.WithFields(logrus.Fields{
		"acctResult": fmt.Sprintf("%#v", acctResult),
	}).Trace("get_acct_entitlements_okay")

	return acctResult.Result, nil
}
