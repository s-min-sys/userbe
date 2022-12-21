package google2fa

import (
	"context"

	"github.com/s-min-sys/protorepo/gens/userpb"
	"github.com/s-min-sys/userbe/internal/po"
	"github.com/sbasestarter/bizuserlib/authenticator/google2fa"
)

func NewServer(authenticator google2fa.Authenticator) userpb.AuthenticatorGoogle2FaServer {
	if authenticator == nil {
		return nil
	}

	return &serverImpl{
		authenticator: authenticator,
	}
}

type serverImpl struct {
	userpb.UnimplementedAuthenticatorGoogle2FaServer

	authenticator google2fa.Authenticator
}

func (impl *serverImpl) GetSetupInfo(ctx context.Context, request *userpb.GetSetupInfoRequest) (*userpb.GetSetupInfoResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.GetSetupInfoResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	secretKey, qrCode, status := impl.authenticator.GetSetupInfo(ctx, request.GetBizId())

	return &userpb.GetSetupInfoResponse{
		Status:    po.Status2Pb(status),
		SecretKey: secretKey,
		QrCode:    qrCode,
	}, nil
}

func (impl *serverImpl) DoSetup(ctx context.Context, request *userpb.DoSetupRequest) (*userpb.DoSetupResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.DoSetupResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	status := impl.authenticator.DoSetup(ctx, request.GetBizId(), request.GetCode())

	return &userpb.DoSetupResponse{
		Status: po.Status2Pb(status),
	}, nil
}

func (impl *serverImpl) Verify(ctx context.Context, request *userpb.VerifyRequest) (*userpb.VerifyResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.VerifyResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	status := impl.authenticator.Verify(ctx, request.GetBizId(), request.GetCode())

	return &userpb.VerifyResponse{
		Status: po.Status2Pb(status),
	}, nil
}
