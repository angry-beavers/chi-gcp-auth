package middleware

import (
	"context"
	"errors"
)

type ctxKey int

const (
	accountContextKey ctxKey = iota
)

type Account struct {
	UUID     string
	Email    string
	TenantId string
}

func AccountFromCtx(ctx context.Context) (Account, error) {
	u, ok := ctx.Value(accountContextKey).(Account)
	if ok {
		return u, nil
	}

	return Account{}, errors.New("account not found in context")
}
