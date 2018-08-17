package authorizer

import (
	"context"

)

type contextKey string

const (
	resultsCtxKey contextKey = "akshonesports authorizer result"
)

type result struct {
	token string
	claims map[string]interface{}
	err error
}

func setToken(ctx context.Context, token string) context.Context {
	ctx, res := getResult(ctx)
	res.token = token
	return ctx
}

func setClaims(ctx context.Context, claims map[string]interface{}) context.Context {
	ctx, res := getResult(ctx)
	res.claims = claims
	return ctx
}

func setError(ctx context.Context, err error) context.Context {
	ctx, res := getResult(ctx)
	res.err = err
	return ctx
}

func getResult(ctx context.Context) (context.Context, *result) {
	res, _ := ctx.Value(resultsCtxKey).(*result)
	if res != nil {
		return ctx, res
	}

	res = &result{}
	return context.WithValue(ctx, resultsCtxKey, res), res
}

func Token(ctx context.Context) string {
	_, res := getResult(ctx)
	return res.token
}

func Claims(ctx context.Context) map[string]interface{} {
	_, res := getResult(ctx)
	return res.claims
}

func Error(ctx context.Context) error {
	_, res := getResult(ctx)
	return res.err
}
