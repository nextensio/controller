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

func IdpGetUser(API string, TOKEN string, userid string) (string, string, string, error) {
	return "", "", "", nil
}

func IdpAddUser(API string, TOKEN string, userid string, tenant string, userType string) (string, error) {
	return "", nil
}

func IdpDelUser(API string, TOKEN string, userid string, tenant string) error {
	return nil
}
