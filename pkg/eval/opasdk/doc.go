/*
	Package opasdk provides fast and light authorization by
    direct call to OPA ingrained as its SDK packages.

	See https://www.openpolicyagent.org/docs/latest/integration/#sdk

	An example of integrating it in services:

	import "github.com/infobloxopen/atlas-authz-middleware/pkg/eval/opasdk"

	interceptors = append(interceptors, opasdk.UnaryServerInterceptor(
		opasdk.ForApplicaton(appID),
		opasdk.WithLogger(logger),
		opasdk.WithBundleResourcePath("/bundle/bundle.tar.gz"),
		opasdk.WithDecisionPath("/authz/rbac/validate_v1"),
		opasdk.WithBundleReloadInterval(time.Minute),
	))
*/
package opasdk
