package router

import (
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
)

var router *mux.Router
var nroni *negroni.Negroni

func addRoute(route string, methods string, handler func(http.ResponseWriter, *http.Request)) {
	router.HandleFunc(route, handler).Methods(methods)
}

// Routes which have handlers that DO NOT modify the database goes here
func initRdOnlyRoutes() {
	rdonlyOnboard()
	rdonlyPolicy()
}

// Routes which have handlers that might modify the database goes here
func initRdWrRoutes() {
	rdwrOnboard()
	rdwrPolicy()
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
	nroni.UseHandler(router)
	initRoutes(readonly)
}

func ServeRoutes() {
	// TODO: The CORS policy allowing "*" needs fixing once we get closer to production
	headersOk := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Referer", "Authorization"})
	originsOk := handlers.AllowedOrigins([]string{"*"})
	methodsOk := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS"})

	http.ListenAndServe(":8080", handlers.CORS(originsOk, headersOk, methodsOk)(nroni))
}
