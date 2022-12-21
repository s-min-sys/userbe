package userserver

import (
	"context"

	"github.com/sgostarter/i/commerr"
	"google.golang.org/grpc/metadata"
)

const (
	tokenKeyOnMetadata = "user_token"
)

func ExtractTokenFromGRPCContext(ctx context.Context) (token string, err error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		err = commerr.ErrUnauthenticated

		return
	}

	tokens := md.Get(tokenKeyOnMetadata)
	if len(tokens) == 0 || tokens[0] == "" {
		err = commerr.ErrUnauthenticated

		return
	}

	token = tokens[0]
	if token == "" {
		err = commerr.ErrNotFound

		return
	}

	return
}
