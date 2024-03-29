package userserver

import (
	"context"
	"time"

	"github.com/s-min-sys/protorepo/gens/userpb"
	"github.com/s-min-sys/userbe/internal/po"
	"github.com/s-min-sys/userbe/internal/usertokenmanager/usertokenmanagerinters"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sgostarter/libeasygo/crypt/simencrypt"
)

func NewServer(userManager bizuserinters.UserManager, userTokenManager usertokenmanagerinters.UserTokenManager, defaultDomain string) userpb.UserServicerServer {
	if userManager == nil {
		return nil
	}

	return &serverImpl{
		userManager:      userManager,
		defaultDomain:    defaultDomain,
		userTokenManager: userTokenManager,
	}
}

type serverImpl struct {
	userpb.UnimplementedUserServicerServer
	userManager      bizuserinters.UserManager
	defaultDomain    string
	userTokenManager usertokenmanagerinters.UserTokenManager

	defaultTokenExpiration time.Duration
}

func (impl *serverImpl) RegisterBegin(ctx context.Context, request *userpb.RegisterBeginRequest) (*userpb.RegisterBeginResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.RegisterBeginResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	bizID, neededOrEvent, status := impl.userManager.RegisterBegin(ctx)

	return &userpb.RegisterBeginResponse{
		Status:         po.Status2Pb(status),
		BizId:          bizID,
		NeededOrEvents: po.AuthenticatorEvents2Pb(neededOrEvent),
	}, nil
}

func (impl *serverImpl) RegisterCheck(ctx context.Context, request *userpb.RegisterCheckRequest) (*userpb.RegisterCheckResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.RegisterCheckResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	neededOrEvent, status := impl.userManager.RegisterCheck(ctx, request.GetBizId())

	return &userpb.RegisterCheckResponse{
		Status:         po.Status2Pb(status),
		NeededOrEvents: po.AuthenticatorEvents2Pb(neededOrEvent),
	}, nil
}

func (impl *serverImpl) RegisterEnd(ctx context.Context, request *userpb.RegisterEndRequest) (*userpb.RegisterEndResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.RegisterEndResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	userInfo, status := impl.userManager.RegisterEnd(ctx, request.GetBizId())
	if status.Code != bizuserinters.StatusCodeOk {
		return &userpb.RegisterEndResponse{
			Status: po.Status2Pb(status),
		}, nil
	}

	///

	tokenExpiration := impl.defaultTokenExpiration

	token, status := impl.userTokenManager.GenToken(ctx, &usertokenmanagerinters.UserTokenInfo{
		ID:         userInfo.ID,
		UserName:   userInfo.UserName,
		Expiration: tokenExpiration,
	})

	if status.Code != bizuserinters.StatusCodeOk {
		return &userpb.RegisterEndResponse{
			Status: po.Status2Pb(status),
		}, nil
	}

	err := impl.SetUserTokenCookie(ctx, token, tokenExpiration)
	if err != nil {
		return &userpb.RegisterEndResponse{
			Status: po.StatusCode2PbWithError(bizuserinters.StatusCodeInternalError, err),
		}, nil
	}

	return &userpb.RegisterEndResponse{
		Status: po.Status2Pb(status),
		UserId: simencrypt.EncryptUInt64(userInfo.ID),
	}, nil
}

func (impl *serverImpl) LoginBegin(ctx context.Context, request *userpb.LoginBeginRequest) (*userpb.LoginBeginResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.LoginBeginResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	bizID, neededOrEvent, status := impl.userManager.LoginBegin(ctx)

	return &userpb.LoginBeginResponse{
		Status:         po.Status2Pb(status),
		BizId:          bizID,
		NeededOrEvents: po.AuthenticatorEvents2Pb(neededOrEvent),
	}, nil
}

func (impl *serverImpl) LoginCheck(ctx context.Context, request *userpb.LoginCheckRequest) (*userpb.LoginCheckResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.LoginCheckResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	neededOrEvent, status := impl.userManager.LoginCheck(ctx, request.GetBizId())

	return &userpb.LoginCheckResponse{
		Status:         po.Status2Pb(status),
		NeededOrEvents: po.AuthenticatorEvents2Pb(neededOrEvent),
	}, nil
}

func (impl *serverImpl) LoginEnd(ctx context.Context, request *userpb.LoginEndRequest) (*userpb.LoginEndResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.LoginEndResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	userInfo, status := impl.userManager.LoginEnd(ctx, request.GetBizId())
	if status.Code != bizuserinters.StatusCodeOk {
		return &userpb.LoginEndResponse{
			Status: po.Status2Pb(status),
		}, nil
	}

	///
	expiration := impl.defaultTokenExpiration

	token, status := impl.userTokenManager.GenToken(ctx, &usertokenmanagerinters.UserTokenInfo{
		ID:         userInfo.ID,
		UserName:   userInfo.UserName,
		Expiration: expiration,
	})

	if status.Code != bizuserinters.StatusCodeOk {
		return &userpb.LoginEndResponse{
			Status: po.Status2Pb(status),
		}, nil
	}

	///

	err := impl.SetUserTokenCookie(ctx, token, expiration)
	if err != nil {
		return &userpb.LoginEndResponse{
			Status: po.StatusCode2PbWithError(bizuserinters.StatusCodeInternalError, err),
		}, nil
	}

	return &userpb.LoginEndResponse{
		Status: po.Status2Pb(status),
		UserId: simencrypt.EncryptUInt64(userInfo.ID),
	}, nil
}

func (impl *serverImpl) ChangeBegin(ctx context.Context, request *userpb.ChangeBeginRequest) (*userpb.ChangeBeginResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.ChangeBeginResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	token, err := ExtractTokenFromGRPCContext(ctx)
	if err != nil {
		return &userpb.ChangeBeginResponse{
			Status: po.StatusCode2PbWithError(bizuserinters.StatusCodePermissionError, err),
		}, nil
	}

	userTokenInfo, status := impl.userTokenManager.ExplainToken(ctx, token)
	if status.Code != bizuserinters.StatusCodeOk {
		return &userpb.ChangeBeginResponse{
			Status: po.Status2Pb(status),
		}, nil
	}

	bizID, neededOrEvent, status := impl.userManager.ChangeBegin(ctx, userTokenInfo.ID, userTokenInfo.UserName,
		po.AuthenticatorIdentitiesFromPb(request.GetAuthenticators()))

	return &userpb.ChangeBeginResponse{
		Status:         po.Status2Pb(status),
		BizId:          bizID,
		NeededOrEvents: po.AuthenticatorEvents2Pb(neededOrEvent),
	}, nil
}

func (impl *serverImpl) ChangeCheck(ctx context.Context, request *userpb.ChangeCheckRequest) (*userpb.ChangeCheckResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.ChangeCheckResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	neededOrEvent, status := impl.userManager.ChangeCheck(ctx, request.GetBizId())

	return &userpb.ChangeCheckResponse{
		Status:         po.Status2Pb(status),
		NeededOrEvents: po.AuthenticatorEvents2Pb(neededOrEvent),
	}, nil
}

func (impl *serverImpl) ChangeEnd(ctx context.Context, request *userpb.ChangeEndRequest) (*userpb.ChangeEndResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.ChangeEndResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	status := impl.userManager.ChangeEnd(ctx, request.GetBizId())

	return &userpb.ChangeEndResponse{
		Status: po.Status2Pb(status),
	}, nil
}

func (impl *serverImpl) DeleteBegin(ctx context.Context, request *userpb.DeleteBeginRequest) (*userpb.DeleteBeginResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.DeleteBeginResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	token, err := ExtractTokenFromGRPCContext(ctx)
	if err != nil {
		return &userpb.DeleteBeginResponse{
			Status: po.StatusCode2PbWithError(bizuserinters.StatusCodePermissionError, err),
		}, nil
	}

	userTokenInfo, status := impl.userTokenManager.ExplainToken(ctx, token)
	if status.Code != bizuserinters.StatusCodeOk {
		return &userpb.DeleteBeginResponse{
			Status: po.Status2Pb(status),
		}, nil
	}

	bizID, neededOrEvent, status := impl.userManager.DeleteBegin(ctx, userTokenInfo.ID, userTokenInfo.UserName,
		po.AuthenticatorIdentitiesFromPb(request.GetAuthenticators()))

	return &userpb.DeleteBeginResponse{
		Status:         po.Status2Pb(status),
		BizId:          bizID,
		NeededOrEvents: po.AuthenticatorEvents2Pb(neededOrEvent),
	}, nil
}

func (impl *serverImpl) DeleteCheck(ctx context.Context, request *userpb.DeleteCheckRequest) (*userpb.DeleteCheckResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.DeleteCheckResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	neededOrEvent, status := impl.userManager.DeleteCheck(ctx, request.GetBizId())

	return &userpb.DeleteCheckResponse{
		Status:         po.Status2Pb(status),
		NeededOrEvents: po.AuthenticatorEvents2Pb(neededOrEvent),
	}, nil
}

func (impl *serverImpl) DeleteEnd(ctx context.Context, request *userpb.DeleteEndRequest) (*userpb.DeleteEndResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.DeleteEndResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	status := impl.userManager.DeleteEnd(ctx, request.GetBizId())

	return &userpb.DeleteEndResponse{
		Status: po.Status2Pb(status),
	}, nil
}

func (impl *serverImpl) ListUsers(ctx context.Context, request *userpb.ListUsersRequest) (*userpb.ListUsersResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.ListUsersResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	token, err := ExtractTokenFromGRPCContext(ctx)
	if err != nil {
		return &userpb.ListUsersResponse{
			Status: po.StatusCode2PbWithError(bizuserinters.StatusCodePermissionError, err),
		}, nil
	}

	_, status := impl.userTokenManager.ExplainToken(ctx, token)
	if status.Code != bizuserinters.StatusCodeOk {
		return &userpb.ListUsersResponse{
			Status: po.Status2Pb(status),
		}, nil
	}

	users, status := impl.userManager.ListUsers(ctx)

	return &userpb.ListUsersResponse{
		Status:    po.Status2Pb(status),
		UserInfos: po.Users2Pb(users),
	}, nil
}

func (impl *serverImpl) CheckToken(ctx context.Context, request *userpb.CheckTokenRequest) (*userpb.CheckTokenResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.CheckTokenResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	token, err := ExtractTokenFromGRPCContext(ctx)
	if err != nil {
		return &userpb.CheckTokenResponse{
			Status: po.StatusCode2PbWithError(bizuserinters.StatusCodePermissionError, err),
		}, nil
	}

	info, status := impl.userTokenManager.ExplainToken(ctx, token)
	if status.Code != bizuserinters.StatusCodeOk {
		return &userpb.CheckTokenResponse{
			Status: po.Status2Pb(status),
		}, nil
	}

	return &userpb.CheckTokenResponse{
		Status:    po.Status2Pb(status),
		TokenInfo: po.UserTokenInfo2Pb(info),
	}, nil
}

func (impl *serverImpl) RenewToken(ctx context.Context, request *userpb.RenewTokenRequest) (*userpb.RenewTokenResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.RenewTokenResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	token, err := ExtractTokenFromGRPCContext(ctx)
	if err != nil {
		return &userpb.RenewTokenResponse{
			Status: po.StatusCode2PbWithError(bizuserinters.StatusCodePermissionError, err),
		}, nil
	}

	newTokenStr, info, status := impl.userTokenManager.RenewToken(ctx, token)
	if status.Code != bizuserinters.StatusCodeOk {
		return &userpb.RenewTokenResponse{
			Status: po.Status2Pb(status),
		}, nil
	}

	err = impl.SetUserTokenCookie(ctx, newTokenStr, info.Expiration)
	if err != nil {
		return &userpb.RenewTokenResponse{
			Status: po.StatusCode2PbWithError(bizuserinters.StatusCodeInternalError, err),
		}, nil
	}

	return &userpb.RenewTokenResponse{
		Status:    po.Status2Pb(status),
		NewToken:  token,
		TokenInfo: po.UserTokenInfo2Pb(info),
	}, nil
}

func (impl *serverImpl) Logout(ctx context.Context, request *userpb.LogoutRequest) (*userpb.LogoutResponse, error) {
	if request == nil || request.ValidateAll() != nil {
		return &userpb.LogoutResponse{
			Status: &userpb.Status{
				Code: userpb.Code_CODE_INVALID_ARGS_ERROR,
			},
		}, nil
	}

	token, err := ExtractTokenFromGRPCContext(ctx)
	if err != nil {
		return &userpb.LogoutResponse{
			Status: po.StatusCode2PbWithError(bizuserinters.StatusCodePermissionError, err),
		}, nil
	}

	_ = impl.UnsetUserTokenCookie(ctx, token)

	status := impl.userTokenManager.DeleteToken(ctx, token)

	return &userpb.LogoutResponse{
		Status: po.Status2Pb(status),
	}, nil
}
