package oauthserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/go-session/session"
	"github.com/gorilla/mux"
	"github.com/phyber/negroni-gzip/gzip"
	"github.com/s-min-sys/userbe/internal/config"
	"github.com/sgostarter/i/commerr"
	"github.com/sgostarter/i/l"
	"github.com/urfave/negroni"
	graceful "gopkg.in/tylerb/graceful.v1"
)

type OAuth2Server interface {
	Go(listen string)
}

const (
	SessionKeyLoggedInUserID = "LoggedInUserID"
	SessionKeyReturnURI      = "ReturnUri"
)

type OAuth2ServerConfigs struct {
	URLLogin          string
	URLAuth           string
	ClientCredentials map[string]config.OAuthClientCredential
}

type LoginHelper interface {
	CheckHTTPLogin(r *http.Request) (userID uint64, userName string, ok bool)
}

func NewOAuth2Server(configs OAuth2ServerConfigs, loginHelper LoginHelper, logger l.Wrapper) OAuth2Server {
	if logger == nil {
		logger = l.NewNopLoggerWrapper()
	}

	if loginHelper == nil {
		logger.Fatal("noLoginHelper")
	}

	return &oAuthServer2Impl{
		configs:     configs,
		loginHelper: loginHelper,
		logger:      logger.WithFields(l.StringField(l.ClsKey, "oAuthServer2Impl")),
	}
}

type oAuthServer2Impl struct {
	configs     OAuth2ServerConfigs
	loginHelper LoginHelper
	logger      l.Wrapper
}

func (impl *oAuthServer2Impl) httpLocationTo(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

func (impl *oAuthServer2Impl) Go(listen string) {
	app := negroni.Classic()
	app.Use(gzip.Gzip(gzip.DefaultCompression))

	// Create a router instance
	router := mux.NewRouter()
	impl.installHandlers(router)

	app.UseHandler(router)

	graceful.Run(listen, 5*time.Second, app)
}

func (impl *oAuthServer2Impl) installHandlers(router *mux.Router) {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// generate jwt access token
	// manager.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS512))
	manager.MapAccessGenerate(generates.NewAccessGenerate())

	clientStore := store.NewClientStore()
	for id, client := range impl.configs.ClientCredentials {
		_ = clientStore.Set(id, &models.Client{
			ID:     id,
			Secret: client.Secret,
			Domain: client.Domain,
		})
	}

	manager.MapClientStorage(clientStore)

	srv := server.NewServer(server.NewConfig(), manager)

	srv.SetPasswordAuthorizationHandler(impl.passwordAuthorizationHandler)
	srv.SetUserAuthorizationHandler(impl.userAuthorizeHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		impl.logger.WithFields(l.ErrorField(err)).Error("internal error")

		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		impl.logger.WithFields(l.ErrorField(re.Error)).Error("response error")
	})

	router.HandleFunc("/oauth/auth", func(w http.ResponseWriter, r *http.Request) {
		userID, _, ok := impl.loginHelper.CheckHTTPLogin(r)
		if !ok {
			impl.httpLocationTo(w, impl.configs.URLLogin)

			return
		}

		storage, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		storage.Set(SessionKeyLoggedInUserID, strconv.FormatUint(userID, 10))

		err = storage.Save()
		if err != nil {
			impl.logger.WithFields(l.ErrorField(err)).Error("save ReturnUri failed")

			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		impl.httpLocationTo(w, "/oauth/authorize")
	})

	router.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		impl.oAuthAuthorizeHandler(w, r, srv)
	})

	router.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			impl.logger.WithFields(l.ErrorField(err)).Error("handle token request failed")

			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	router.HandleFunc("/oauth/test", func(w http.ResponseWriter, r *http.Request) {
		token, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		}

		data := map[string]interface{}{
			// nolint: gosimple
			"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
			"client_id":  token.GetClientID(),
			"user_id":    token.GetUserID(),
		}

		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		_ = e.Encode(data)
	})
}

func (impl *oAuthServer2Impl) passwordAuthorizationHandler(ctx context.Context, clientID, username, password string) (userID string, err error) {
	err = commerr.ErrUnimplemented

	return
}

func (impl *oAuthServer2Impl) userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	storage, err := session.Start(r.Context(), w, r)
	if err != nil {
		return
	}

	uid, ok := storage.Get(SessionKeyLoggedInUserID)
	if !ok {
		if r.Form == nil {
			_ = r.ParseForm()
		}

		storage.Set(SessionKeyReturnURI, r.Form)
		_ = storage.Save()

		impl.httpLocationTo(w, impl.configs.URLLogin)

		return
	}

	userID, _ = uid.(string)

	storage.Delete(SessionKeyReturnURI)

	_ = storage.Save()

	return
}

func (impl *oAuthServer2Impl) oAuthAuthorizeHandler(w http.ResponseWriter, r *http.Request, srv *server.Server) {
	storage, err := session.Start(r.Context(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	var form url.Values

	if v, ok := storage.Get(SessionKeyReturnURI); ok {
		form, _ = v.(url.Values)
	}

	r.Form = form

	storage.Delete(SessionKeyReturnURI)

	err = storage.Save()
	if err != nil {
		impl.logger.WithFields(l.ErrorField(err)).Error("save ReturnUri failed")

		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	err = srv.HandleAuthorizeRequest(w, r)
	if err != nil {
		impl.logger.WithFields(l.ErrorField(err)).Error("handle authorize request failed")

		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}
