package authorizer

import (
	"context"

	"github.com/dgrijalva/jwt-go"
)

type contextKey string

const (
	claimsCtxKey contextKey = "authorizer jwt claims"
	errorCtxKey  contextKey = "authorizer error"
)

func withResult(ctx context.Context, claims jwt.MapClaims, err error) context.Context {
	ctx = context.WithValue(ctx, claimsCtxKey, map[string]interface{}(claims))
	ctx = context.WithValue(ctx, errorCtxKey, err)
	return ctx
}

func Claims(ctx context.Context) map[string]interface{} {
	claims, _ := ctx.Value(claimsCtxKey).(map[string]interface{})
	return claims
}

func Error(ctx context.Context) error {
	err, _ := ctx.Value(errorCtxKey).(error)
	return err
}
