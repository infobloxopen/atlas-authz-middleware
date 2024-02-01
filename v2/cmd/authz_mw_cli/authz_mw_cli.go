// authz_mw_cli - atlas-authz-middleware CLI for testing purposes
//
// To build/run:
// $ cd .../atlas-authz-middleware
// $ make bin
// $ bin/authz_mw_cli

package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	opamw "github.com/infobloxopen/atlas-authz-middleware/v2/grpc_opa"
	opacl "github.com/infobloxopen/atlas-authz-middleware/pkg/opa_client"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"

	logrus "github.com/sirupsen/logrus"

	az "github.com/infobloxopen/atlas-authz-middleware/v2/common/authorizer"
	"google.golang.org/grpc/metadata"
)

func usageAndExit() {
	fmt.Fprintf(os.Stderr, strings.Replace(`
Usage: AUTHZ_MW_CLI <ip:port> validate <decisionDoc> <app> <endpoint> <jwt>
Usage: AUTHZ_MW_CLI <ip:port> acct_entitlements <acct_id,...> <service,...>
<ip:port> can be empty string, which will default to 'localhost:8181'
<decisionDoc> can be empty string, which will default to OPA's configured default decision doc

Example:
$ kubectl -n authz port-forward pod/authz-dbapi-5d7ff9fb49-ghz5c 18181:8181
$ AUTHZ_MW_CLI localhost:18181 validate '' authz EffectivePermissions.GetEffectivePermissions <jwt>
$ AUTHZ_MW_CLI localhost:18181 validate '/v1/data/authz/rbac/validate_v1' authz EffectivePermissions.GetEffectivePermissions <jwt>
$ AUTHZ_MW_CLI localhost:18181 acct_entitlements 16,40 ddi,rpz

`, `AUTHZ_MW_CLI`, os.Args[0], -1))
	logrus.Exit(0)
}

func main() {
	if len(os.Args) < 3 {
		usageAndExit()
	}

	opaIpPort := os.Args[1]
	if len(opaIpPort) <= 0 {
		opaIpPort = opacl.DefaultAddress
	}
	if !strings.HasPrefix(opaIpPort, `http://`) {
		opaIpPort = `http://` + opaIpPort
	}

	stdLoggr := logrus.StandardLogger()
	stdLoggr.SetLevel(logrus.TraceLevel)
	ctx, cancelCtxFn := context.WithCancel(context.Background())
	ctx = ctxlogrus.ToContext(ctx, logrus.NewEntry(stdLoggr))
	defer func() {
		cancelCtxFn()
	}()

	switch strings.ToLower(os.Args[2]) {
	case `validate`:
		validate(ctx, opaIpPort)
	case `acct_entitlements`:
		acct_entitlements(ctx, opaIpPort)
	default:
		usageAndExit()
	}
}

func validate(ctx context.Context, opaIpPort string) {
	loggr := ctxlogrus.Extract(ctx)

	if len(os.Args) < 7 {
		usageAndExit()
	}

	decisionDoc := os.Args[3]
	app := os.Args[4]
	fullMethod := os.Args[5]
	jwt := os.Args[6]

	// Ensure fullMethod is in GRPC fullMethod format acceptable by middleware
	if matched, _ := regexp.MatchString(`^[[:alnum:]]+\.[[:alnum:]]+$`, fullMethod); matched {
		fullMethod = strings.Replace(fullMethod, `.`, `/`, -1)
		fullMethod = `/service.` + fullMethod
	}

	// Middleware will add `/` prefix to decisionDoc document, so remove it
	decisionDoc = strings.TrimPrefix(decisionDoc, `/`)

	// From https://github.com/grpc-ecosystem/go-grpc-middleware/blob/master/auth/metadata_test.go
	bearer := fmt.Sprintf(`bearer %s`, jwt)
	md := metadata.Pairs(`authorization`, bearer)
	ctx = metautils.NiceMD(md).ToIncoming(ctx)

	loggr.Infof("opaIpPort=`%s`\n", opaIpPort)
	loggr.Infof("decisionDoc=`%s`\n", decisionDoc)
	loggr.Infof("app=`%s`\n", app)
	loggr.Infof("fullMethod=`%s`\n", fullMethod)

	var decInputr MyDecisionInputr
	decInputr.DecisionInput.DecisionDocument = decisionDoc

	authzr := opamw.NewDefaultAuthorizer(app,
		opamw.WithAddress(opaIpPort),
		opamw.WithDecisionInputHandler(&decInputr),
	)

	resultCtx, resultErr := authzr.AffirmAuthorization(ctx, fullMethod, nil)

	loggr.Infof("resultErr=%#v", resultErr)
	loggr.Infof("resultCtx=%#v", resultCtx)
}

func acct_entitlements(ctx context.Context, opaIpPort string) {
	loggr := ctxlogrus.Extract(ctx)

	if len(os.Args) < 5 {
		usageAndExit()
	}

	acct_idsComma := os.Args[3]
	servicesComma := os.Args[4]

	acct_ids := strings.Split(acct_idsComma, `,`)
	services := strings.Split(servicesComma, `,`)

	loggr.Infof("opaIpPort=`%s`\n", opaIpPort)
	loggr.Infof("acct_ids=%s\n", acct_ids)
	loggr.Infof("services=%s\n", services)

	fmt.Fprintf(os.Stderr, "acct_entitlements not implemented yet\n")
}

type MyDecisionInputr struct {
	az.DecisionInput
}

func (d MyDecisionInputr) GetDecisionInput(ctx context.Context, fullMethod string, grpcReq interface{}) (*az.DecisionInput, error) {
	return &d.DecisionInput, nil
}
