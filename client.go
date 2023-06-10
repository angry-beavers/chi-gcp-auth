package middleware

import (
	"context"
	"errors"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"google.golang.org/api/option"
)

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
