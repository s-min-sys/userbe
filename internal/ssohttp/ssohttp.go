package ssohttp

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/s-min-sys/protorepo/gens/userpb"
	"github.com/s-min-sys/userbe/pkg/grpctoken"
)

type Server interface {
	ListenAndServe(address string)
}

func NewServer(grpcServer userpb.UserServicerServer, defaultDomain string) Server {
	if grpcServer == nil {
		return nil
	}

	return &serverImpl{
		grpcServer:    grpcServer,
		defaultDomain: defaultDomain,
	}
}

type SSOLoginRequest struct {
	SSOToken string `json:"sso_token"`
}

type SSOLoginResponse struct {
	Token             string `json:"token"`
	ExpirationSeconds int    `json:"expiration_seconds"`
}

type serverImpl struct {
	grpcServer    userpb.UserServicerServer
	defaultDomain string
}

func (impl *serverImpl) ListenAndServe(address string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sso/login", impl.SSOLogin)

	s := http.Server{
		Addr:              address,
		Handler:           mux,
		ReadHeaderTimeout: time.Second * 10,
	}

	_ = s.ListenAndServe()
}

func (impl *serverImpl) SSOLogin(writer http.ResponseWriter, request *http.Request) {
	statusCode, token, expirationSeconds, err := impl.ssoLogin(request)
	if statusCode != http.StatusOK {
		writer.WriteHeader(statusCode)

		if err != nil {
			_, _ = writer.Write([]byte(err.Error()))
		}

		return
	}

	domain := impl.domainFromHTTPRequest(request)
	if domain == "" {
		domain = impl.defaultDomain
	}

	cookie := &http.Cookie{
		Domain:   domain,
		Name:     grpctoken.TokenKeyOnMetadata,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   expirationSeconds,
	}

	http.SetCookie(writer, cookie)

	d, err := json.Marshal(&SSOLoginResponse{
		Token:             token,
		ExpirationSeconds: expirationSeconds,
	})
	if err != nil {
		writer.WriteHeader(statusCode)

		if err != nil {
			_, _ = writer.Write([]byte(err.Error()))
		}

		return
	}

	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(d)
}

func (impl *serverImpl) ssoLogin(request *http.Request) (statusCode int, token string,
	expirationSeconds int, err error) {
	if !strings.EqualFold(request.Method, http.MethodPost) {
		statusCode = http.StatusNotFound

		return
	}

	defer request.Body.Close()

	d, err := io.ReadAll(request.Body)
	if err != nil {
		statusCode = http.StatusBadRequest

		return
	}

	var req SSOLoginRequest

	err = json.Unmarshal(d, &req)
	if err != nil {
		statusCode = http.StatusBadRequest

		return
	}

	if req.SSOToken == "" {
		statusCode = http.StatusNonAuthoritativeInfo

		return
	}

	resp, err := impl.grpcServer.SSOLogin(request.Context(), &userpb.SSOLoginRequest{
		SsoToken:      req.SSOToken,
		SetCookieFlag: false,
	})
	if err != nil {
		statusCode = http.StatusInternalServerError

		return
	}

	if resp == nil || resp.GetStatus() == nil {
		statusCode = http.StatusInternalServerError

		return
	}

	if resp.GetStatus().GetCode() != userpb.Code_CODE_OK {
		statusCode = http.StatusInternalServerError
		err = errors.New(resp.GetStatus().GetMessage())

		return
	}

	token = resp.GetToken()

	statusCode = http.StatusOK
	expirationSeconds = int(resp.GetTokenExpirationSeconds())

	return
}

//
//
//

func (impl *serverImpl) domainFromHTTPRequest(request *http.Request) (domain string) {
	h := request.Host
	if h == "" {
		h = request.URL.Host
	}

	if h == "" {
		return
	}

	domain = h

	if idx := strings.Index(domain, "://"); idx != -1 {
		domain = domain[idx+3:]
	}

	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[0:idx]
	}

	domain = strings.Trim(domain, " \r\n\t")

	return
}
