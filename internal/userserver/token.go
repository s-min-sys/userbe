package userserver

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/s-min-sys/userbe/pkg/grpctoken"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func ExtractTokenFromGRPCContext(ctx context.Context) (token string, err error) {
	token = grpctoken.GetStringFromGRPCContext(ctx, grpctoken.TokenKeyOnMetadata)

	return
}

func (impl *serverImpl) SetUserTokenCookie(ctx context.Context, token string, expiration time.Duration) error {
	domain := impl.domainFromGRPCContext(ctx)

	if domain == "" {
		domain = impl.defaultDomain
	}

	cookie := http.Cookie{
		Domain:   domain,
		Name:     grpctoken.TokenKeyOnMetadata,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   int(expiration.Seconds()),
	}

	return grpc.SendHeader(ctx, metadata.Pairs("Set-Cookie", cookie.String()))
}

func (impl *serverImpl) UnsetUserTokenCookie(ctx context.Context, token string) error {
	domain := impl.domainFromGRPCContext(ctx)

	if domain == "" {
		domain = impl.defaultDomain
	}

	cookie := http.Cookie{
		Domain:   domain,
		Name:     grpctoken.TokenKeyOnMetadata,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	}

	return grpc.SendHeader(ctx, metadata.Pairs("Set-Cookie", cookie.String()))
}

func (impl *serverImpl) domainFromGRPCContext(ctx context.Context) (domain string) {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		values := md.Get("origin")
		if len(values) > 0 {
			domain = values[0]
		}
	}

	if idx := strings.Index(domain, "://"); idx != -1 {
		domain = domain[idx+3:]
	}

	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[0:idx]
	}

	domain = strings.Trim(domain, " \r\n\t")

	return
}
