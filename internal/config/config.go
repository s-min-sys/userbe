package config

import (
	"sync"

	"github.com/sgostarter/i/l"
	"github.com/sgostarter/libconfig"
	"github.com/sgostarter/liblogrus"
	"github.com/sgostarter/libservicetoolset/servicetoolset"
)

type Config struct {
	Logger l.Wrapper `yaml:"-"`

	Listen        string                            `yaml:"Listen"`
	WebListen     string                            `yaml:"WebListen"`
	GRPCTLSConfig *servicetoolset.GRPCTlsFileConfig `yaml:"GRPCTLSConfig"`
	SSOHttpListen string                            `yaml:"SSOHttpListen"`

	RedisDSN     string `yaml:"RedisDSN"`
	UserMongoDSN string `yaml:"UserMongoDSN"`

	DefaultDomain    string   `yaml:"DefaultDomain"`
	SSOJumpWhiteList []string `yaml:"SSOJumpWhiteList"`

	DebugCfg DebugCfg `yaml:"DebugCfg"`
}

type DebugCfgAuthenticatorGoogle2FA struct {
	FakeQrCode    string `yaml:"FakeQrCode"`
	FakeSecretKey string `yaml:"FakeSecretKey"`
}

type DebugCfg struct {
	AuthenticatorGoogle2FA *DebugCfgAuthenticatorGoogle2FA `yaml:"AuthenticatorGoogle2FA"`
}

var (
	_cfg  Config
	_once sync.Once
)

func GetConfig() *Config {
	_once.Do(func() {
		_cfg.Logger = l.NewWrapper(liblogrus.NewLogrus())
		_cfg.Logger.GetLogger().SetLevel(l.LevelDebug)

		_, err := libconfig.Load("config.yaml", &_cfg)
		if err != nil {
			panic("load config: " + err.Error())
		}
	})

	return &_cfg
}
