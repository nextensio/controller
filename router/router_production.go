// +build !unittest

package router

import (
	"context"
	"net/http"
	"nextensio/controller/okta"
	"nextensio/controller/utils"
)

func Authenticate(w http.ResponseWriter, r *http.Request) *context.Context {
	// The Agents/Connectors and other UX/SDK-users are kept as seperate applications
	// in the IDP (okta), mainly because all of them have seperate redirect-urls in their
	// configs. So we need to validate the token against one of either client ids
	cidMobileAgent := utils.GetEnv("AGENT_MOB_CLIENT_ID", "none")
	ctx := IsAuthenticated(r, cidMobileAgent)
	if ctx == nil {
		cidApi := utils.GetEnv("API_CLIENT_ID", "none")
		ctx = IsAuthenticated(r, cidApi)
		if ctx == nil {
			cidSpaAgent := utils.GetEnv("AGENT_SPA_CLIENT_ID", "none")
			ctx = IsAuthenticated(r, cidSpaAgent)
		}
	}

	return ctx
}

func IdpGetUserInfo(API string, TOKEN string, userid string) (string, string, string, error) {
	return okta.GetUserInfo(API, TOKEN, userid)
}

func IdpAddUser(API string, TOKEN string, userid string, tenant string, userType string, signup bool) (string, error) {
	return okta.AddUser(API, TOKEN, userid, tenant, userType, signup)
}

func IdpDelUser(API string, TOKEN string, userid string, tenant string) error {
	return okta.DelUser(API, TOKEN, userid, tenant)
}

func IdpAddUserToGroup(API string, TOKEN string, groupid string, userid string, ulogin string, signup bool) error {
	return okta.AddToGroup(API, TOKEN, groupid, userid, ulogin, signup)
}

func IdpGetGroupID(API string, TOKEN string, tenant string) (string, error) {
	return okta.GetGroupID(API, TOKEN, tenant)
}

func IdpAddGroup(API string, TOKEN string, tenant string, signup bool) (string, error) {
	return okta.AddGroup(API, TOKEN, tenant, signup)
}

func IdpDelGroup(API string, TOKEN string, tenant string) error {
	return okta.DelGroup(API, TOKEN, tenant)
}
