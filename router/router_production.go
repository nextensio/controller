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

	if ctx == nil {
		// TODO: This is TERRIBLE, a potential security threat to have this kind
		// of a variable lying around. Move all internal testbeds to use proper
		// https + authentication and remove this crap
		if utils.GetEnv("IGNORE_AUTH", "false") == "true" {
			ctx := context.WithValue(r.Context(), "usertype", "superadmin")
			return &ctx
		} else {
			return nil
		}
	}
	return ctx
}

func IdpAddUser(API string, TOKEN string, userid string, tenant string, userType string) (string, error) {
	return okta.AddUser(API, TOKEN, userid, tenant, userType)
}

func IdpDelUser(API string, TOKEN string, userid string, tenant string) error {
	return okta.DelUser(API, TOKEN, userid, tenant)
}
