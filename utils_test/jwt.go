package utils_test

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/metadata"
)

func NewContextWithJWTClaims(log *logrus.Logger, ctx context.Context, claims jwt.MapClaims) context.Context {
	token, err := MakeJWTFromClaims(claims)
	if err != nil {
		log.Fatalf("MakeJWTFromClaims err: %v", err)
	}

	return NewContextWithJWT(ctx, token)
}

// MakeJWTFromClaims generates a jwt string based on the given jwt claims
func MakeJWTFromClaims(claims jwt.Claims) (string, error) {
	method := jwt.SigningMethodHS256
	token := jwt.NewWithClaims(method, claims)
	signingString, err := token.SigningString()
	if err != nil {
		return "", err
	}
	signature, err := method.Sign(signingString, []byte("some-secret-123"))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", signingString, signature), nil
}

// NewContextWithJWT creates a context with a jwt
func NewContextWithJWT(ctx context.Context, jwtStr string) context.Context {
	return metadata.NewIncomingContext(ctx, metadata.Pairs("Authorization", fmt.Sprintf("Bearer %s", jwtStr)))
}
