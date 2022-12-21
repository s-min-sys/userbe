package anonymous

import (
	"context"

	"github.com/s-min-sys/protorepo/gens/userpb"
	"github.com/s-min-sys/userbe/internal/po"
	"github.com/sbasestarter/bizuserlib/authenticator/anonymous"
)

func NewServer(authenticator anonymous.Authenticator) userpb.AuthenticatorAnonymousServer {
	if authenticator == nil {
		return nil
	}

	return &serverImpl{
		authenticator: authenticator,
	}
}

type serverImpl struct {
	userpb.UnimplementedAuthenticatorAnonymousServer

	authenticator anonymous.Authenticator
}

func (impl *serverImpl) SetUserName(ctx context.Context, request *userpb.SetUserNameRequest) (*userpb.SetUserNameResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.SetUserNameResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	status := impl.authenticator.SetUserName(ctx, request.GetBizId(), request.GetUserName())

	return &userpb.SetUserNameResponse{
		Status: po.Status2Pb(status),
	}, nil
}
