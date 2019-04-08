package authorizer

import (
	"context"

)

type contextKey struct{}

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

func setResult(ctx context.Context, res *result) context.Context {
	return context.WithValue(ctx, contextKey{}, res)
}

func getResult(ctx context.Context) (context.Context, *result) {
	res, _ := ctx.Value(contextKey{}).(*result)
	if res != nil {
		return ctx, res
	}

	res = &result{}
	return setResult(ctx, res), res
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
