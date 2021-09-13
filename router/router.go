package router

import (
	"context"
	"fmt"
	"net/http"
	"nextensio/controller/db"
	"nextensio/controller/utils"
	"regexp"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	verifier "github.com/okta/okta-jwt-verifier-golang"
	"github.com/urfave/negroni"
)

var router *mux.Router
var global *mux.Router
var noauth *mux.Router
var globalGet *mux.Router
var globalAdd *mux.Router
var globalDel *mux.Router
var tenant *mux.Router
var tenantGet *mux.Router
var tenantAdd *mux.Router
var tenantDel *mux.Router
var nroni *negroni.Negroni
var IDP string
var API string
var TOKEN string

func getGlobalRoute(route string, methods string, handler func(http.ResponseWriter, *http.Request)) {
	globalGet.HandleFunc(route, handler).Methods(methods)
}

func addGlobalRoute(route string, methods string, handler func(http.ResponseWriter, *http.Request)) {
	globalAdd.HandleFunc(route, handler).Methods(methods)
}

func delGlobalRoute(route string, methods string, handler func(http.ResponseWriter, *http.Request)) {
	globalDel.HandleFunc(route, handler).Methods(methods)
}

func getTenantRoute(route string, methods string, handler func(http.ResponseWriter, *http.Request)) {
	tenantGet.HandleFunc(route, handler).Methods(methods)
}

func addTenantRoute(route string, methods string, handler func(http.ResponseWriter, *http.Request)) {
	tenantAdd.HandleFunc(route, handler).Methods(methods)
}

func delTenantRoute(route string, methods string, handler func(http.ResponseWriter, *http.Request)) {
	tenantDel.HandleFunc(route, handler).Methods(methods)
}

func noauthRoute(route string, methods string, handler func(http.ResponseWriter, *http.Request)) {
	noauth.HandleFunc(route, handler).Methods(methods)
}

// Routes which have handlers that DO NOT modify the database goes here
func initRdOnlyRoutes() {
	rdonlyOnboard()
	rdonlyPolicy()
	rdonlyRoute()
}

// Routes which have handlers that might modify the database goes here
func initRdWrRoutes() {
	rdwrOnboard()
	rdwrPolicy()
	rdwrRoute()
}

func initRoutes(readonly bool) {
	initRdOnlyRoutes()
	if readonly {
		return
	}
	initRdWrRoutes()
}

func oktaJwt(r *http.Request, bearerToken string, cid string) *context.Context {
	idp := utils.GetEnv("IDP_URI", "none")
	tv := map[string]string{}
	tv["aud"] = "api://default"
	tv["cid"] = cid
	jv := verifier.JwtVerifier{
		Issuer:           idp,
		ClaimsToValidate: tv,
	}

	token, err := jv.New().VerifyAccessToken(bearerToken)
	if err != nil {
		fmt.Println("Not verified", cid, err)
		return nil
	}
	// TODO: The access token presented in bearer is supposed to be an opaque entity
	// as per OIDC standards, but Okta allows us to fit things in there and decode it
	// etc... Ideally we are supposed to use the ID Token here. So at some point when
	// we move to say Azure as IDP, we might run into trouble here at which point we
	// will have to somehow send the ID token also to get these values
	uuid := token.Claims["tenant"].(string)
	ctx := context.WithValue(r.Context(), "user-tenant", uuid)
	ctx = context.WithValue(ctx, "userid", token.Claims["sub"])
	ctx = context.WithValue(ctx, "usertype", token.Claims["usertype"])
	return &ctx
}

func IsAuthenticated(r *http.Request, cid string) *context.Context {
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		return nil
	}
	tokenParts := strings.Split(authHeader, "Bearer ")
	bearerToken := tokenParts[1]
	// First try to interpret the token as an agent's okta token, if that fails
	// then try to see if its a connectors token we generated
	ctx := oktaJwt(r, bearerToken, cid)
	if ctx != nil {
		return ctx
	}
	ctx = db.VerifyMyJwt(r, bearerToken)
	return ctx
}

// TODO: This checking for whether non-superadmin/admin is trying to access add/del
// etc.. is quite clunky below, need to make that code flow more modular/simpler
// The logic is that if the request is onboarding, then we allow that regardless of
// the user privilege. Other requests are denied unless the user is superadmin, the
// "global" nextensio resources can be add/mod/del only by nextensio superadmin
func GlobalMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	ctx := Authenticate(w, r)
	if ctx == nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("401 - You are not authorized for this request"))
		return
	}
	url := r.URL.String()
	reg, _ := regexp.Compile("/api/v1/global/(add|get|del)/([a-zA-Z0-9]+).*")
	match := reg.FindStringSubmatch(url)
	if len(match) != 3 {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Bad request url"))
		return
	}
	allowed := (match[1] == "get" && match[2] == "onboard")
	if !allowed {
		allowed = (match[1] == "get" && strings.HasPrefix(match[2], "keepalive"))
	}
	usertype := (*ctx).Value("usertype").(string)
	if usertype != "superadmin" && !allowed {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("User unauthorized to global resources"))
		return
	}
	next.ServeHTTP(w, r.WithContext(*ctx))
}

// TODO: This checking for whether non-superadmin/admin is trying to access add/del
// etc.. is quite clunky below, need to make that code flow more modular/simpler.
// The logic here is as follows
// 1. A superadmin can access ALL tenants, ie /tenant/<any-id> is valid for super admin
// 2. An admin can access only one tenant, ie /tenant/<any-id> where <any-id> is the
//    tenant-id mentioned in the admins access token
// 3. A support can access only one tenant AND only have read-only (get) access
// 4. A regular user cant access anything
//
// NOTE: user-tenant and tenant might be a bit confusing. user-tenant is the tenant
// that the user is part of. And tenant is the tenant that the user wants to modify/act on
// In the case of superadmin, both can be different because superadmins can act on any
// tenant. But for all other users, both should match
func TenantMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	ctx := Authenticate(w, r)
	if ctx == nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("401 - You are not authorized for this request"))
		return
	}

	url := r.URL.String()
	reg, _ := regexp.Compile("/api/v1/tenant/([a-z0-9]+)/(add|get|del)/([_a-zA-Z0-9]+).*")
	match := reg.FindStringSubmatch(url)
	if len(match) != 4 {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Bad request url"))
		return
	}
	uuid := match[1]
	usertype := (*ctx).Value("usertype").(string)
	if usertype != "superadmin" {
		userTenant := (*ctx).Value("user-tenant").(string)
		if userTenant != uuid {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("User unauthorized to access this tenant"))
			return
		}
	}

	// support user, only read-only access allowed
	if usertype == "support" {
		if match[2] != "get" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("User unauthorized to modify this tenant"))
			return
		}
	}

	// regular user, not allowed anything
	if usertype == "regular" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("User not authorized acess to this tenant"))
		return
	}

	ctx1 := context.WithValue(*ctx, "tenant", uuid)
	next.ServeHTTP(w, r.WithContext(ctx1))
}

func NoauthMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	next.ServeHTTP(w, r)
}

func RouterInit(readonly bool) {
	router = mux.NewRouter().StrictSlash(false)

	global = router.PathPrefix("/api/v1/global/").Subrouter()
	globalGet = global.PathPrefix("/get/").Subrouter()
	globalAdd = global.PathPrefix("/add/").Subrouter()
	globalDel = global.PathPrefix("/del/").Subrouter()

	tenant = router.PathPrefix("/api/v1/tenant/{tenant-uuid}/").Subrouter()
	tenantGet = tenant.PathPrefix("/get/").Subrouter()
	tenantAdd = tenant.PathPrefix("/add/").Subrouter()
	tenantDel = tenant.PathPrefix("/del/").Subrouter()

	noauth = router.PathPrefix("/api/v1/noauth/").Subrouter()

	superMux := http.NewServeMux()
	superMux.Handle("/api/v1/global/", negroni.New(
		negroni.HandlerFunc(GlobalMiddleware),
		negroni.Wrap(router),
	))
	superMux.Handle("/api/v1/tenant/", negroni.New(
		negroni.HandlerFunc(TenantMiddleware),
		negroni.Wrap(router),
	))
	superMux.Handle("/api/v1/noauth/", negroni.New(
		negroni.HandlerFunc(NoauthMiddleware),
		negroni.Wrap(router),
	))

	nroni = negroni.New()
	nroni.UseHandler(superMux)

	initRoutes(readonly)
}

func ServeRoutes() {
	// TODO: The CORS policy allowing "*" needs fixing once we get closer to production
	headersOk := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Referer", "Authorization"})
	originsOk := handlers.AllowedOrigins([]string{"*"})
	methodsOk := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS"})

	IDP = utils.GetEnv("IDP_URI", "none") + "/v1"
	API = utils.GetEnv("IDP_API", "none")
	TOKEN = utils.GetEnv("API_TOKEN", "none")
	cert := utils.GetEnv("TLS_CRT", "unknown")
	key := utils.GetEnv("TLS_KEY", "unknown")
	if cert == "unknown" || key == "unknown" {
		http.ListenAndServe(":8080", handlers.CORS(originsOk, headersOk, methodsOk)(nroni))
	} else {
		http.ListenAndServeTLS(":8080", cert, key, handlers.CORS(originsOk, headersOk, methodsOk)(nroni))
	}
}
