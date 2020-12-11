package grpc_opa_middleware

// // Initialization shows a relatively complex initialization sequence.
// func Example_initialization() {
// 	_ = grpc.NewServer(
// 		grpc_middleware.WithUnaryServerChain(
// 			UnaryServerInterceptor("app"),
// 		),
// 	)
// }

// func Example_custom_querier() {

// 	customQuerier := QueryFn(func(ctx context.Context, fullMethodName string, cli *opa_client.Client) (interface{}, bool, error) {
// 		return &struct{}{}, false, nil
// 	})

// 	_ = grpc.NewServer(
// 		grpc_middleware.WithUnaryServerChain(
// 			UnaryServerInterceptor("app",
// 				WithQuerier(customQuerier),
// 				WithHTTPClient(http.DefaultClient),
// 				WithAddress(opa_client.DefaultAddress),
// 			),
// 		),
// 	)

// }
