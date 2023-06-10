package middleware

import (
	"context"
	"net/http"

	"firebase.google.com/go/auth"
)

type Authenticator interface {
	TokenVerifier(next http.Handler) http.Handler
}

type authMiddleware struct {
	AuthClient *auth.Client
}

func NewGcpAuthMiddleware(client *auth.Client) *authMiddleware {
	return &authMiddleware{
		AuthClient: client,
	}
}

func (a authMiddleware) TokenVerifier(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		bearerToken := a.tokenFromHeader(r)
		if bearerToken == "" {
			http.Error(w, "no token presented", http.StatusUnauthorized)
			return
		}

		token, err := a.AuthClient.VerifyIDToken(ctx, bearerToken)
		if err != nil {
			http.Error(w, "unable to verify token", http.StatusUnauthorized)
			return
		}

		ctx = context.WithValue(ctx, accountContextKey, Account{
			UUID:     token.UID,
			Email:    token.Claims["email"].(string),
			TenantId: token.Firebase.Tenant,
		})
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
