package po

import (
	"github.com/s-min-sys/protorepo/gens/userpb"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

func StatusCode2Pb(code bizuserinters.StatusCode) userpb.Code {
	switch code {
	case bizuserinters.StatusCodeOk:
		return userpb.Code_CODE_OK
	case bizuserinters.StatusCodeNeedAuthenticator:
		return userpb.Code_CODE_NEED_AUTHENTICATOR
	case bizuserinters.StatusCodeNotCompleted:
		return userpb.Code_CODE_NOT_COMPLETED
	case bizuserinters.StatusCodeNoDataError:
		return userpb.Code_CODE_NO_DATA_ERROR
	case bizuserinters.StatusCodeInvalidArgsError:
		return userpb.Code_CODE_INVALID_ARGS_ERROR
	case bizuserinters.StatusCodeInternalError:
		return userpb.Code_CODE_INTERNAL_ERROR
	case bizuserinters.StatusCodeExistsError:
		return userpb.Code_CODE_EXISTS_ERROR
	case bizuserinters.StatusCodeNotImplementError:
		return userpb.Code_CODE_NOT_IMPLEMENT_ERROR
	case bizuserinters.StatusCodeConflictError:
		return userpb.Code_CODE_CONFLICT_ERROR
	case bizuserinters.StatusCodeExpiredError:
		return userpb.Code_CODE_EXPIRED_ERROR
	case bizuserinters.StatusCodeLogicError:
		return userpb.Code_CODE_LOGIC_ERROR
	case bizuserinters.StatusCodeDupError:
		return userpb.Code_CODE_DUP_ERROR
	case bizuserinters.StatusCodeVerifyError:
		return userpb.Code_CODE_VERIFY_ERROR
	case bizuserinters.StatusCodeBadDataError:
		return userpb.Code_CODE_BAD_DATA_ERROR
	case bizuserinters.StatusCodePermissionError:
		return userpb.Code_CODE_PERMISSION_ERROR
	}

	return userpb.Code_CODE_UNSPECIFIED
}

func Status2Pb(status bizuserinters.Status) *userpb.Status {
	return Status2PbWithError(status, nil)
}

func Status2PbWithError(status bizuserinters.Status, err error) *userpb.Status {
	pbStatus := &userpb.Status{
		Code:    StatusCode2Pb(status.Code),
		Message: status.Message,
	}

	if pbStatus.Message == "" && err != nil {
		pbStatus.Message = err.Error()
	}

	return pbStatus
}

func StatusCode2PbWithError(code bizuserinters.StatusCode, err error) *userpb.Status {
	pbStatus := &userpb.Status{
		Code: StatusCode2Pb(code),
	}

	if pbStatus.Message == "" && err != nil {
		pbStatus.Message = err.Error()
	}

	return pbStatus
}
