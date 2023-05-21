package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"google.golang.org/api/option"
)

type Authenticator interface {
	TokenVerifier(next http.Handler) http.Handler
}

type Account struct {
	UUID     string
	Email    string
	TenantId string
}

type ctxKey int

const (
	accountContextKey ctxKey = iota
)

func AccountFromCtx(ctx context.Context) (Account, error) {
	u, ok := ctx.Value(accountContextKey).(Account)
	if ok {
		return u, nil
	}

	return Account{}, errors.New("account not found in context")
}

type authMiddleware struct {
	AuthClient *auth.Client
}

func NewGcpDefaultClient(ctx context.Context, projectId string, opts ...option.ClientOption) (*auth.Client, error) {
	config := &firebase.Config{ProjectID: projectId}
	firebaseApp, err := firebase.NewApp(ctx, config, opts...)
	if err != nil {
		return nil, errors.New("error initializing app: %v\n" + err.Error())
	}

	client, err := firebaseApp.Auth(ctx)
	if err != nil {
		return nil, errors.New("Unable to create firebase Auth client: %v\n" + err.Error())
	}

	return client, nil
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

func (a authMiddleware) tokenFromHeader(r *http.Request) string {
	headerValue := r.Header.Get("Authorization")

	if len(headerValue) > 7 && strings.ToLower(headerValue[0:6]) == "bearer" {
		return headerValue[7:]
	}

	return ""
}
