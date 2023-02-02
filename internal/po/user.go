package po

import (
	"github.com/s-min-sys/protorepo/gens/userpb"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

func User2Pb(userInfo *bizuserinters.UserInfo) *userpb.UserInfo {
	if userInfo == nil {
		return nil
	}

	return &userpb.UserInfo{
		Id:            userInfo.ID,
		UserName:      userInfo.UserName,
		HasGoogle_2Fa: userInfo.HasGoogle2FA,
		Admin:         userInfo.Admin,
	}
}

func Users2Pb(userInfos []*bizuserinters.UserInfo) []*userpb.UserInfo {
	us := make([]*userpb.UserInfo, 0, len(userInfos))

	for _, info := range userInfos {
		us = append(us, User2Pb(info))
	}

	return us
}
