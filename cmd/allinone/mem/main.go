package main

import (
	"time"

	"github.com/s-min-sys/protorepo/gens/userpb"
	"github.com/s-min-sys/userbe/internal/authenticatorserver/admin"
	"github.com/s-min-sys/userbe/internal/authenticatorserver/google2fa"
	"github.com/s-min-sys/userbe/internal/authenticatorserver/userpass"
	"github.com/s-min-sys/userbe/internal/config"
	"github.com/s-min-sys/userbe/internal/oauthserver"
	"github.com/s-min-sys/userbe/internal/server"
	"github.com/s-min-sys/userbe/internal/userserver"
	"github.com/s-min-sys/userbe/internal/usertokenmanager"
	"github.com/sbasestarter/bizuserlib/model/authenticator/model"
	"github.com/sbasestarter/bizuserlib/tokenmanager"
	"github.com/sgostarter/libservicetoolset/servicetoolset"
	"google.golang.org/grpc"
)

func main() {
	cfg := config.GetConfig()

	logger := cfg.Logger

	tlsConfig, err := servicetoolset.GRPCTlsConfigMap(cfg.GRPCTLSConfig)
	if err != nil {
		logger.Fatal(err)
	}

	grpcCfg := &servicetoolset.GRPCServerConfig{
		Address:                  cfg.Listen,
		TLSConfig:                tlsConfig,
		KeepAliveDuration:        time.Minute * 10,
		EnforcementPolicyMinTime: time.Second * 10,
		WebAddress:               cfg.WebListen,
	}

	s, err := servicetoolset.NewGRPCServer(nil, grpcCfg, nil, nil, logger)
	if err != nil {
		logger.Fatal(err)

		return
	}

	tokenManager := tokenmanager.NewMemoryTokenManager()
	jwtDataStorage := usertokenmanager.NewMemoryJWTDataStorage()
	dbModel := model.NewMemoryDBModel(tokenManager)
	instances := server.NewInstances(tokenManager, jwtDataStorage, dbModel, cfg)

	us := userserver.NewServer(instances.UserManager, instances.UserTokenManager, cfg.DefaultDomain)

	err = s.Start(func(s *grpc.Server) error {
		userpb.RegisterUserServicerServer(s, us)
		userpb.RegisterAuthenticatorUserPassServer(s, userpass.NewServer(instances.UserPassAuthenticator))
		userpb.RegisterAuthenticatorGoogle2FaServer(s, google2fa.NewServer(instances.Google2FAAuthenticator))
		userpb.RegisterAuthenticatorAdminServer(s, admin.NewServer(instances.AdminAuthenticator))

		return nil
	})
	if err != nil {
		logger.Fatal(err)

		return
	}

	cfg.Logger.Info("Server Listen on :", cfg.Listen)

	if cfg.OAuthListen != "" {
		go func() {
			oAuthServer := oauthserver.NewOAuth2Server(oauthserver.OAuth2ServerConfigs{
				URLLogin:          "/biz?op=login&redirected=oauth",
				URLAuth:           "/auth",
				ClientCredentials: cfg.OAuthClientCredentials,
			}, oauthserver.NewLoginHelper(instances.UserTokenManager), nil)
			oAuthServer.Go(cfg.OAuthListen)
		}()
	}

	s.Wait()
}
