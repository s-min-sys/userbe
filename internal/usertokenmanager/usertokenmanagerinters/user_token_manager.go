package usertokenmanagerinters

import (
	"context"
	"time"

	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

type UserTokenInfo struct {
	ID         uint64
	UserName   string
	StartAt    time.Time
	Expiration time.Duration
}

type UserTokenManager interface {
	GenToken(ctx context.Context, userInfo *UserTokenInfo) (string, bizuserinters.Status)
	ExplainToken(ctx context.Context, token string) (*UserTokenInfo, bizuserinters.Status)
	RenewToken(ctx context.Context, token string) (string, *UserTokenInfo, bizuserinters.Status)

	GenSSOToken(ctx context.Context, parentToken string, expiration time.Duration) (string, bizuserinters.Status)
	ExplainSSOToken(ctx context.Context, token string) (*UserTokenInfo, bizuserinters.Status)

	DeleteToken(ctx context.Context, token string) bizuserinters.Status
}
