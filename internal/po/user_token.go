package po

import (
	"github.com/s-min-sys/protorepo/gens/userpb"
	"github.com/s-min-sys/userbe/internal/usertokenmanager/usertokenmanagerinters"
)

func UserTokenInfo2Pb(info *usertokenmanagerinters.UserTokenInfo) *userpb.UserTokenInfo {
	if info == nil {
		return nil
	}

	return &userpb.UserTokenInfo{
		Id:       info.ID,
		UserName: info.UserName,
		StartAt:  info.StartAt.Unix(),
		Age:      int64(info.Expiration.Seconds()),
	}
}
