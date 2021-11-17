// +build unittest

package router

import (
	"context"
	"net/http"
)

func Authenticate(w http.ResponseWriter, r *http.Request) *context.Context {
	ctx := context.WithValue(r.Context(), "usertype", "superadmin")
	return &ctx
}

func IdpGetUserInfo(API string, TOKEN string, userid string) (string, string, string, error) {
	return "", "", "", nil
}

func IdpAddUser(API string, TOKEN string, userid string, tenant string, userType string, signup bool) (string, error) {
	return "", nil
}

func IdpDelUser(API string, TOKEN string, userid string, tenant string) error {
	return nil
}

func IdpAddUserToGroup(API string, TOKEN string, groupid string, userid string, ulogin string, signup bool) error {
	return nil
}

func IdpGetGroupID(API string, TOKEN string, tenant string) (string, error) {
	return "", nil
}

func IdpAddGroup(API string, TOKEN string, tenant string, signup bool) (string, error) {
	return "", nil
}

func IdpDelGroup(API string, TOKEN string, tenant string) error {
	return nil
}
