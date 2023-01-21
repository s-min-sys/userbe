package po

import (
	"github.com/s-min-sys/protorepo/gens/userpb"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

func UserTokenInfo2Pb(info *bizuserinters.UserTokenInfo, origin string) *userpb.UserTokenInfo {
	if info == nil {
		return nil
	}

	return &userpb.UserTokenInfo{
		Id:       info.ID,
		UserName: info.UserName,
		StartAt:  info.StartAt.Unix(),
		Age:      int64(info.Expiration.Seconds()),
		Origin:   origin,
	}
}
