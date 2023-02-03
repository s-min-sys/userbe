package oauthserver

import (
	"net/http"

	"github.com/s-min-sys/userbe/internal/usertokenmanager/usertokenmanagerinters"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

func NewLoginHelper(userTokenManager usertokenmanagerinters.UserTokenManager) LoginHelper {
	if userTokenManager == nil {
		return nil
	}

	return &loginHelperImpl{
		userTokenManager: userTokenManager,
	}
}

type loginHelperImpl struct {
	userTokenManager usertokenmanagerinters.UserTokenManager
}

func (impl *loginHelperImpl) CheckHTTPLogin(r *http.Request) (userID uint64, userName string, ok bool) {
	cookie, err := r.Cookie("user_token")
	if err != nil {
		return
	}

	user, status := impl.userTokenManager.ExplainToken(r.Context(), cookie.Value)
	if status.Code != bizuserinters.StatusCodeOk {
		return
	}

	userID = user.ID
	userName = user.UserName
	ok = true

	return
}
