package userpass

import (
	"context"

	"github.com/s-min-sys/protorepo/gens/userpb"
	"github.com/s-min-sys/userbe/internal/po"
	"github.com/sbasestarter/bizuserlib/authenticator/userpass"
)

func NewServer(authenticator userpass.Authenticator) userpb.AuthenticatorUserPassServer {
	if authenticator == nil {
		return nil
	}

	return &serverImpl{
		authenticator: authenticator,
	}
}

type serverImpl struct {
	userpb.UnimplementedAuthenticatorUserPassServer

	authenticator userpass.Authenticator
}

func (impl *serverImpl) Register(ctx context.Context, request *userpb.RegisterRequest) (*userpb.RegisterResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.RegisterResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	status := impl.authenticator.Register(ctx, request.GetBizId(), request.GetUserName(), request.GetPassword())

	return &userpb.RegisterResponse{
		Status: po.Status2Pb(status),
	}, nil
}

func (impl *serverImpl) Login(ctx context.Context, request *userpb.LoginRequest) (*userpb.LoginResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.LoginResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	status := impl.authenticator.Login(ctx, request.GetBizId(), request.GetUserName(), request.GetPassword())

	return &userpb.LoginResponse{
		Status: po.Status2Pb(status),
	}, nil
}

func (impl *serverImpl) VerifyPassword(ctx context.Context, request *userpb.VerifyPasswordRequest) (*userpb.VerifyPasswordResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.VerifyPasswordResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	status := impl.authenticator.VerifyPassword(ctx, request.GetPassword(), request.GetPassword())

	return &userpb.VerifyPasswordResponse{
		Status: po.Status2Pb(status),
	}, nil
}

func (impl *serverImpl) ChangePassword(ctx context.Context, request *userpb.ChangePasswordRequest) (*userpb.ChangePasswordResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.ChangePasswordResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	status := impl.authenticator.ChangePassword(ctx, request.GetPassword(), request.GetPassword())

	return &userpb.ChangePasswordResponse{
		Status: po.Status2Pb(status),
	}, nil
}
