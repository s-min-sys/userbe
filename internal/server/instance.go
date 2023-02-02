package server

import (
	"github.com/s-min-sys/userbe/internal/config"
	"github.com/s-min-sys/userbe/internal/usertokenmanager"
	"github.com/s-min-sys/userbe/internal/usertokenmanager/usertokenmanagerinters"
	"github.com/sbasestarter/bizuserlib"
	"github.com/sbasestarter/bizuserlib/authenticator/admin"
	"github.com/sbasestarter/bizuserlib/authenticator/google2fa"
	"github.com/sbasestarter/bizuserlib/authenticator/userpass"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
	authenticatorinters "github.com/sbasestarter/bizuserlib/bizuserinters/model/authenticator"
	"github.com/sbasestarter/bizuserlib/model/authenticator"
	"github.com/sbasestarter/bizuserlib/model/authenticator/model"
	"github.com/sbasestarter/bizuserlib/policy"
)

type Instances struct {
	UserManager            bizuserinters.UserManager
	UserTokenManager       usertokenmanagerinters.UserTokenManager
	UserPassAuthenticator  userpass.Authenticator
	Google2FAAuthenticator google2fa.Authenticator
	AdminAuthenticator     admin.Authenticator
}

func NewInstances(tokenManagerAll bizuserinters.TokenManagerAll, jwtDataStorage usertokenmanagerinters.JWTDataStorage,
	dbModel authenticatorinters.DBModel, cfg *config.Config) *Instances {
	userTokenManager := usertokenmanager.NewJWTUserTokenManager("x", jwtDataStorage)
	ply := policy.DefaultConditionAuthenticatorPolicy(tokenManagerAll)

	userManagerModel := model.NewUserManagerModel(dbModel)

	userManager := bizuserlib.NewUserManager(tokenManagerAll, ply, ply, ply, ply, userManagerModel, dbModel, nil)

	tokenManagerModel := authenticator.NewDirectTokenManagerModel(tokenManagerAll)
	userPassModel := model.NewUserPassModel(dbModel, tokenManagerModel)

	userPassAuthenticator := userpass.NewAuthenticator(userPassModel, "x")

	cacheMode := authenticator.NewMemoryCacheModel()
	google2FAModel := model.NewGoogle2FAModel(dbModel, tokenManagerModel, cacheMode)

	google2FAAuthenticator := google2fa.NewAuthenticator(google2FAModel, "stw.com")

	if cfg.DebugCfg.AuthenticatorGoogle2FA != nil {
		google2FAAuthenticator = google2fa.NewAuthenticatorEx(google2FAModel, "stw.com", &google2fa.DebugConfig{
			FakeQrURL:     cfg.DebugCfg.AuthenticatorGoogle2FA.FakeQrCode,
			FakeSecretKey: cfg.DebugCfg.AuthenticatorGoogle2FA.FakeSecretKey,
		})
	}

	adminModel := model.NewAdminModel(dbModel, tokenManagerModel)
	adminAuthenticator := admin.NewAuthenticator(adminModel)

	return &Instances{
		UserManager:            userManager,
		UserTokenManager:       userTokenManager,
		UserPassAuthenticator:  userPassAuthenticator,
		Google2FAAuthenticator: google2FAAuthenticator,
		AdminAuthenticator:     adminAuthenticator,
	}
}
