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
	"google.golang.org/grpc/metadata"
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
	Origin            string `json:"origin"`
}

type serverImpl struct {
	grpcServer    userpb.UserServicerServer
	defaultDomain string
}

func (impl *serverImpl) ListenAndServe(address string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sso/login", impl.SSOLogin)
	mux.HandleFunc("/user/profile", impl.UserProfile)

	s := http.Server{
		Addr:              address,
		Handler:           mux,
		ReadHeaderTimeout: time.Second * 10,
	}

	_ = s.ListenAndServe()
}

type UserInfo struct {
	ID       uint64 `json:"id"`
	UserName string `json:"user_name"`
	Origin   string `json:"origin"`
}

func (impl *serverImpl) UserProfile(writer http.ResponseWriter, request *http.Request) {
	statusCode, userID, userName, origin, err := impl.userProfile(request)
	if statusCode != http.StatusOK {
		writer.WriteHeader(statusCode)

		if err != nil {
			_, _ = writer.Write([]byte(err.Error()))
		}

		return
	}

	d, err := json.Marshal(&UserInfo{
		ID:       userID,
		UserName: userName,
		Origin:   origin,
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

func (impl *serverImpl) userProfile(request *http.Request) (statusCode int, userID uint64, userName, origin string, err error) {
	defer request.Body.Close()

	cookie, err := request.Cookie(grpctoken.TokenKeyOnMetadata)
	if err != nil {
		statusCode = http.StatusUnauthorized

		return
	}

	if cookie.Value == "" {
		statusCode = http.StatusUnauthorized

		return
	}

	// direct call, so use NewIncomingContext
	resp, err := impl.grpcServer.CheckToken(metadata.NewIncomingContext(request.Context(), metadata.New(map[string]string{
		grpctoken.TokenKeyOnMetadata: cookie.Value,
	})), &userpb.CheckTokenRequest{})
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

	userID = resp.GetTokenInfo().GetId()
	userName = resp.GetTokenInfo().GetUserName()
	origin = resp.GetTokenInfo().GetOrigin()

	statusCode = http.StatusOK

	return
}

func (impl *serverImpl) SSOLogin(writer http.ResponseWriter, request *http.Request) {
	statusCode, token, origin, expirationSeconds, err := impl.ssoLogin(request)
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
		Origin:            origin,
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

func (impl *serverImpl) ssoLogin(request *http.Request) (statusCode int, token, origin string,
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
	origin = resp.GetOrigin()

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
