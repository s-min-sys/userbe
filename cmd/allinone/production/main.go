package main

import (
	"time"

	"github.com/s-min-sys/protorepo/gens/userpb"
	"github.com/s-min-sys/userbe/internal/authenticatorserver/admin"
	"github.com/s-min-sys/userbe/internal/authenticatorserver/google2fa"
	"github.com/s-min-sys/userbe/internal/authenticatorserver/userpass"
	"github.com/s-min-sys/userbe/internal/config"
	"github.com/s-min-sys/userbe/internal/server"
	"github.com/s-min-sys/userbe/internal/userserver"
	"github.com/sbasestarter/bizuserlib/impl/mongo/model/authenticator/model"
	"github.com/sbasestarter/bizuserlib/impl/redis/tokenmanager"
	"github.com/sbasestarter/bizuserlib/impl/redis/usertokenmanager"
	"github.com/sgostarter/libeasygo/stg/mongoex"
	"github.com/sgostarter/libeasygo/stg/redisex"
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
	}

	s, err := servicetoolset.NewGRPCServer(nil, grpcCfg, nil, nil, logger)
	if err != nil {
		logger.Fatal(err)

		return
	}

	// "redis://:redis_default_pass@127.0.0.1:8300/0"
	redisCli, err := redisex.InitRedis(cfg.RedisDSN)
	if err != nil {
		logger.Fatal(err)

		return
	}

	tokenManager := tokenmanager.NewRedisTokenManager(redisCli, "", nil)
	jwtDataStorage := usertokenmanager.NewRedisJWTDataStorage(redisCli, nil)
	// "mongodb://mongo_default_user:mongo_default_pass@127.0.0.1:8309/my_db"
	mongoCli, opts, err := mongoex.InitMongo(cfg.UserMongoDSN)
	if err != nil {
		logger.Fatal(err)

		return
	}

	dbModel := model.NewMongoDBModel(mongoCli, opts.Auth.AuthSource, "users", tokenManager, nil)
	instances := server.NewInstances(tokenManager, jwtDataStorage, dbModel)

	err = s.Start(func(s *grpc.Server) error {
		userpb.RegisterUserServicerServer(s, userserver.NewServer(instances.UserManager))
		userpb.RegisterAuthenticatorUserPassServer(s, userpass.NewServer(instances.UserPassAuthenticator))
		userpb.RegisterAuthenticatorGoogle2FaServer(s, google2fa.NewServer(instances.Google2FAAuthenticator))
		userpb.RegisterAuthenticatorAdminServer(s, admin.NewServer(instances.AdminAuthenticator))

		return nil
	})
	if err != nil {
		logger.Fatal(err)

		return
	}

	s.Wait()
}
