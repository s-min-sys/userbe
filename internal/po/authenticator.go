package po

import (
	"github.com/s-min-sys/protorepo/gens/userpb"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
)

func AuthenticatorIdentityFromPb(authenticator userpb.AuthenticatorIdentity) bizuserinters.AuthenticatorIdentity {
	switch authenticator {
	case userpb.AuthenticatorIdentity_AUTHENTICATOR_IDENTITY_USER:
		return bizuserinters.AuthenticatorUser
	case userpb.AuthenticatorIdentity_AUTHENTICATOR_IDENTITY_ANONYMOUS:
		return bizuserinters.AuthenticatorAnonymous
	case userpb.AuthenticatorIdentity_AUTHENTICATOR_IDENTITY_USER_PASS:
		return bizuserinters.AuthenticatorUserPass
	case userpb.AuthenticatorIdentity_AUTHENTICATOR_IDENTITY_USER_PASS_PASS:
		return bizuserinters.AuthenticatorUserPassPass
	case userpb.AuthenticatorIdentity_AUTHENTICATOR_IDENTITY_PHONE:
		return bizuserinters.AuthenticatorPhone
	case userpb.AuthenticatorIdentity_AUTHENTICATOR_IDENTITY_EMAIL:
		return bizuserinters.AuthenticatorEmail
	case userpb.AuthenticatorIdentity_AUTHENTICATOR_IDENTITY_GOOGLE_2FA:
		return bizuserinters.AuthenticatorGoogle2FA
	case userpb.AuthenticatorIdentity_AUTHENTICATOR_IDENTITY_ADMIN_FLAG:
		return bizuserinters.AuthenticatorAdminFlag
	}

	return bizuserinters.AuthenticatorUnspecified
}

func AuthenticatorIdentitiesFromPb(authenticators []userpb.AuthenticatorIdentity) []bizuserinters.AuthenticatorIdentity {
	as := make([]bizuserinters.AuthenticatorIdentity, 0, len(authenticators))

	for _, authenticator := range authenticators {
		as = append(as, AuthenticatorIdentityFromPb(authenticator))
	}

	return as
}

func AuthenticatorIdentity2Pb(authenticator bizuserinters.AuthenticatorIdentity) userpb.AuthenticatorIdentity {
	switch authenticator {
	case bizuserinters.AuthenticatorUser:
		return userpb.AuthenticatorIdentity_AUTHENTICATOR_IDENTITY_USER
	case bizuserinters.AuthenticatorAnonymous:
		return userpb.AuthenticatorIdentity_AUTHENTICATOR_IDENTITY_ANONYMOUS
	case bizuserinters.AuthenticatorUserPass:
		return userpb.AuthenticatorIdentity_AUTHENTICATOR_IDENTITY_USER_PASS
	case bizuserinters.AuthenticatorUserPassPass:
		return userpb.AuthenticatorIdentity_AUTHENTICATOR_IDENTITY_USER_PASS_PASS
	case bizuserinters.AuthenticatorPhone:
		return userpb.AuthenticatorIdentity_AUTHENTICATOR_IDENTITY_PHONE
	case bizuserinters.AuthenticatorEmail:
		return userpb.AuthenticatorIdentity_AUTHENTICATOR_IDENTITY_EMAIL
	case bizuserinters.AuthenticatorGoogle2FA:
		return userpb.AuthenticatorIdentity_AUTHENTICATOR_IDENTITY_GOOGLE_2FA
	case bizuserinters.AuthenticatorAdmin:
		return userpb.AuthenticatorIdentity_AUTHENTICATOR_IDENTITY_UNSPECIFIED
	case bizuserinters.AuthenticatorAdminFlag:
		return userpb.AuthenticatorIdentity_AUTHENTICATOR_IDENTITY_ADMIN_FLAG
	}

	return userpb.AuthenticatorIdentity_AUTHENTICATOR_IDENTITY_UNSPECIFIED
}

func Event2Pb(event bizuserinters.Event) userpb.Event {
	switch event {
	case bizuserinters.SetupEvent:
		return userpb.Event_EVENT_SETUP
	case bizuserinters.VerifyEvent:
		return userpb.Event_EVENT_VERIFY
	case bizuserinters.DeleteEvent:
		return userpb.Event_EVENT_DELETE
	}

	return userpb.Event_EVENT_UNSPECIFIED
}

func AuthenticatorEvent2Pb(e bizuserinters.AuthenticatorEvent) *userpb.AuthenticatorEvent {
	return &userpb.AuthenticatorEvent{
		Authenticator: AuthenticatorIdentity2Pb(e.Authenticator),
		Event:         Event2Pb(e.Event),
	}
}

func AuthenticatorEvents2Pb(es []bizuserinters.AuthenticatorEvent) (pbEs []*userpb.AuthenticatorEvent) {
	pbEs = make([]*userpb.AuthenticatorEvent, 0, len(es))

	for _, e := range es {
		pbEs = append(pbEs, AuthenticatorEvent2Pb(e))
	}

	return
}
