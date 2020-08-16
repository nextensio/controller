package main

import (
	"net/http"
	"nextensio/controller/utils"
	"regexp"

	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
)

type userinfoResult struct {
	Sub string `json:"sub"`
}

// A dummy userinfo handler where we just return the access token itself as the user / sub field
func userinfoHandler(w http.ResponseWriter, r *http.Request) {
	var result userinfoResult
	bearer := r.Header.Get("Authorization")
	re, _ := regexp.Compile(`\s*Bearer\s*(.*)`)
	token := re.FindStringSubmatch(bearer)
	result.Sub = token[1]
	utils.WriteResult(w, result)
}

func initRoutes() {
	router := mux.NewRouter()
	nroni := negroni.New()
	nroni.UseHandler(router)
	router.HandleFunc("/test/api/v1/userinfo", userinfoHandler).Methods("GET")
	http.ListenAndServe(":8081", nroni)
}

func main() {
	initRoutes()
}
