package grpctoken

import (
	"context"
	"strings"

	"github.com/sgostarter/libeasygo/strutils"
	"github.com/sgostarter/libservicetoolset/grpce/meta"
	"google.golang.org/grpc/metadata"
)

const (
	TokenKeyOnMetadata = "user_token"
)

func GetCookieStringFromGRPCContext(ctx context.Context, key string) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	values := md.Get("cookie")
	values = append(values, md.Get("ymicookie")...)

	if len(values) == 0 {
		return ""
	}

	for _, value := range values {
		cookies := strings.Split(value, ";")
		for _, cookie := range cookies {
			ps := strings.SplitN(cookie, "=", 2)
			if len(ps) != 2 {
				continue
			}

			if strutils.StringTrim(ps[0]) == key {
				return strutils.StringTrim(ps[1])
			}
		}
	}

	return ""
}

func GetStringFromGRPCContext(ctx context.Context, key string) string {
	token := GetCookieStringFromGRPCContext(ctx, key)
	if token != "" {
		return token
	}

	token, _ = meta.GetStringFromMeta(ctx, key)

	return token
}
