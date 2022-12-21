package admin

import (
	"context"

	"github.com/s-min-sys/protorepo/gens/userpb"
	"github.com/s-min-sys/userbe/internal/po"
	"github.com/sbasestarter/bizuserlib/authenticator/admin"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sgostarter/libeasygo/crypt/simencrypt"
)

func NewServer(authenticator admin.Authenticator) userpb.AuthenticatorAdminServer {
	if authenticator == nil {
		return nil
	}

	return &serverImpl{
		authenticator: authenticator,
	}
}

type serverImpl struct {
	userpb.UnimplementedAuthenticatorAdminServer

	authenticator admin.Authenticator
}

func (impl *serverImpl) SetAdminFlag(ctx context.Context, request *userpb.SetAdminFlagRequest) (*userpb.SetAdminFlagResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.SetAdminFlagResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	userID, err := simencrypt.DecryptUint64(request.GetUserId())
	if err != nil || userID == 0 {
		return &userpb.SetAdminFlagResponse{
			Status: po.StatusCode2PbWithError(bizuserinters.StatusCodeInvalidArgsError, err),
		}, nil
	}

	status := impl.authenticator.SetAdmin(ctx, request.GetBizId(), userID, request.GetAdminFlag())

	return &userpb.SetAdminFlagResponse{
		Status: po.Status2Pb(status),
	}, nil
}
