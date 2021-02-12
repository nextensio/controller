package router

import (
	"fmt"
	"net/http"
	"nextensio/controller/utils"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	verifier "github.com/okta/okta-jwt-verifier-golang"
	"github.com/urfave/negroni"
)

type oktaAuth struct{}

var router *mux.Router
var nroni *negroni.Negroni
var IDP string

func isAuthenticated(r *http.Request, cid string) bool {
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		return false
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

	_, err := jv.New().VerifyAccessToken(bearerToken)
	if err != nil {
		fmt.Println("Not verified", cid)
		return false
	}

	return true
}

func (*oktaAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	// TODO: This doesnt smell right, a potential security threat to have this kind
	// of a variable lying around. Figure out what else to do to enable a test setup
	// to access the controller without having to authenticate etc..
	if utils.GetEnv("IGNORE_AUTH", "false") == "true" {
		next.ServeHTTP(w, r)
		return
	}
	if r.Method == "OPTIONS" {
		next.ServeHTTP(w, r)
		return
	}

	// The Agents/Connectors and other UX/SDK-users are kept as two seperate applications
	// in the IDP (okta), mainly because both of them have seperate redirect-urls in their
	// configs. So we need to validate the token against one of either client ids
	cidAgent := utils.GetEnv("AGENT_CLIENT_ID", "none")
	cidApi := utils.GetEnv("API_CLIENT_ID", "none")
	if !isAuthenticated(r, cidAgent) && !isAuthenticated(r, cidApi) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("401 - You are not authorized for this request"))
		return
	}
	next.ServeHTTP(w, r)
}

func addRoute(route string, methods string, handler func(http.ResponseWriter, *http.Request)) {
	router.HandleFunc(route, handler).Methods(methods)
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

func RouterInit(readonly bool) {
	router = mux.NewRouter()
	nroni = negroni.New()
	nroni.Use(&oktaAuth{})
	nroni.UseHandler(router)
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
