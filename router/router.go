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
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type oktaAuth struct{}

var router *mux.Router
var global *mux.Router
var globalGet *mux.Router
var globalAdd *mux.Router
var globalDel *mux.Router
var tenant *mux.Router
var tenantGet *mux.Router
var tenantAdd *mux.Router
var tenantDel *mux.Router
var nroni *negroni.Negroni
var IDP string

func isAuthenticated(r *http.Request, cid string) *context.Context {
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		return nil
	}
	tokenParts := strings.Split(authHeader, "Bearer ")
	bearerToken := tokenParts[1]

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
	uuid, err := db.StrToObjectid(token.Claims["tenant"].(string))
	if err != nil {
		fmt.Println("Bad tenant", token.Claims["tenant"].(string))
		return nil
	}
	ctx := context.WithValue(r.Context(), "user-tenant", uuid)
	ctx = context.WithValue(ctx, "userid", token.Claims["sub"])
	ctx = context.WithValue(ctx, "usertype", token.Claims["usertype"])
	return &ctx
}

func (*oktaAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	// The Agents/Connectors and other UX/SDK-users are kept as seperate applications
	// in the IDP (okta), mainly because all of them have seperate redirect-urls in their
	// configs. So we need to validate the token against one of either client ids
	cidMobileAgent := utils.GetEnv("AGENT_MOB_CLIENT_ID", "none")
	ctx := isAuthenticated(r, cidMobileAgent)
	if ctx == nil {
		cidApi := utils.GetEnv("API_CLIENT_ID", "none")
		ctx = isAuthenticated(r, cidApi)
		if ctx == nil {
			cidSpaAgent := utils.GetEnv("AGENT_SPA_CLIENT_ID", "none")
			ctx = isAuthenticated(r, cidSpaAgent)
		}
	}
	if ctx == nil {
		// TODO: This is TERRIBLE, a potential security threat to have this kind
		// of a variable lying around. Move all internal testbeds to use proper
		// https + authentication and remove this crap
		if utils.GetEnv("IGNORE_AUTH", "false") == "true" {
			ctx := context.WithValue(r.Context(), "usertype", "superadmin")
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("401 - You are not authorized for this request"))
			return
		}
	}
	next.ServeHTTP(w, r.WithContext(*ctx))
}

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

func GlobalMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	usertype := r.Context().Value("usertype").(string)
	if usertype != "superadmin" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("User unauthorized to global resources"))
		return
	}
	next.ServeHTTP(w, r)
}

func TenantMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	url := r.URL.String()
	reg, _ := regexp.Compile("/api/v1/tenant/([a-f0-9]*)/.*")
	match := reg.FindStringSubmatch(url)
	if len(match) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Missing tenant id"))
		return
	}
	uuid, err := db.StrToObjectid(match[1])
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Bad tenant id"))
		return
	}
	usertype := r.Context().Value("usertype").(string)
	if usertype != "superadmin" {
		userTenant := r.Context().Value("user-tenant").(primitive.ObjectID)
		if userTenant != uuid {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("User unauthorized to access this tenant"))
			return
		}
	}
	ctx := context.WithValue(r.Context(), "tenant", uuid)
	next.ServeHTTP(w, r.WithContext(ctx))
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

	superMux := http.NewServeMux()
	superMux.Handle("/api/v1/global/", negroni.New(
		negroni.HandlerFunc(GlobalMiddleware),
		negroni.Wrap(router),
	))
	superMux.Handle("/api/v1/tenant/", negroni.New(
		negroni.HandlerFunc(TenantMiddleware),
		negroni.Wrap(router),
	))

	nroni = negroni.New()
	nroni.Use(&oktaAuth{})
	nroni.UseHandler(superMux)

	initRoutes(readonly)
}

func ServeRoutes() {
	// TODO: The CORS policy allowing "*" needs fixing once we get closer to production
	headersOk := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Referer", "Authorization"})
	originsOk := handlers.AllowedOrigins([]string{"*"})
	methodsOk := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS"})

	IDP = utils.GetEnv("IDP_URI", "http://127.0.0.1:8081/test/api") + "/v1"
	cert := utils.GetEnv("TLS_CRT", "unknown")
	key := utils.GetEnv("TLS_KEY", "unknown")
	if cert == "unknown" || key == "unknown" {
		http.ListenAndServe(":8080", handlers.CORS(originsOk, headersOk, methodsOk)(nroni))
	} else {
		http.ListenAndServeTLS(":8080", cert, key, handlers.CORS(originsOk, headersOk, methodsOk)(nroni))
	}
}
