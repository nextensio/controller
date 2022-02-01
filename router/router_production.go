//go:build !unittest
// +build !unittest

package router

import (
	"context"
	"net/http"
	"nextensio/controller/okta"
	"nextensio/controller/utils"
)

func Authenticate(w http.ResponseWriter, r *http.Request) *context.Context {

	cidApi := utils.GetEnv("API_CLIENT_ID", "none")
	return IsAuthenticated(r, cidApi)
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

func IdpGetUsersByType(API string, TOKEN string, tenant string, usertype string) ([]string, error) {
	return okta.GetUsersByType(API, TOKEN, tenant, usertype)
}
