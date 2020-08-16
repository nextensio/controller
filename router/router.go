package router

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"nextensio/controller/db"
	"nextensio/controller/utils"

	"github.com/golang/glog"
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
	// This route is used by the agent while onboarding, agent presents access-token, device-id and
	// tenant-id and expects to get information like the gateway in response
	addRoute("/api/v1/onboard/{access-token}/{device-id}/{tenant-uuid}", "GET", onboardHandler)
}

// Routes which have handlers that might modify the database goes here
func initRdWrRoutes() {
	// This route is used by the controller admin to addd a new tenant
	addRoute("/api/v1/addtenant", "POST", addtenantHandler)

	// This route is used to add new gateways, gateways can be multi-tenant
	addRoute("/api/v1/addgateway", "POST", addgatewayHandler)
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
	http.ListenAndServe(":8080", nroni)
}

type AddtenantResult struct {
	Result string `json:"Result"`
}

// Add a new tenant, with information like the SSO engine used by the
// customers/agents in the tenant
func addtenantHandler(w http.ResponseWriter, r *http.Request) {
	var result AddtenantResult
	var data db.Tenant

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		result.Result = "Error parsing json"
		utils.WriteResult(w, result)
		return
	}
	err = db.DBAddTenant(&data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type AddgatewayResult struct {
	Result string `json:"Result"`
}

// Add a Nextensio gateway gateway
func addgatewayHandler(w http.ResponseWriter, r *http.Request) {
	var result AddgatewayResult
	var data db.Gateway

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		result.Result = "Error parsing json"
		utils.WriteResult(w, result)
		return
	}
	err = db.DBAddGateway(&data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type onboardData struct {
	User string `json:"sub"`
}
type OnboardResult struct {
	Result   string   `json:"Result"`
	Gateways []string `json:"gateways"`
}

// An agent wants to be onboarded, verify its access-token and return
// information that the agent wants, like the NXT gateway to use etc.
// TODO: We are assuming that all the Outh2 servers will have a "userinfo"
// end point and that all of them will return the user id in the "sub" field
// etc. This will for sure not be the case across different Oauth servers and
// will end up needing rework as we support different ones (okta, google, azure etc.)
func onboardHandler(w http.ResponseWriter, r *http.Request) {
	var result OnboardResult
	var data onboardData

	v := mux.Vars(r)
	access := v["access-token"]
	device := v["device-id"]
	uuid := v["tenant-uuid"]

	tenant := db.DBFindTenant(uuid)
	if tenant == nil {
		result.Result = "Tenant not found"
		utils.WriteResult(w, result)
		return
	}
	req, err := http.NewRequest("GET", tenant.Idp+"/userinfo", nil)
	if err != nil {
		result.Result = "Userinfo req failed"
		utils.WriteResult(w, result)
		return
	}
	req.Header.Add("Authorization", "Bearer "+access)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		result.Result = "Userinfo get failed"
		utils.WriteResult(w, result)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		result.Result = "Userinfo read fail"
		utils.WriteResult(w, result)
		return
	}

	// Right now we are just checking that the acess-token gave us some valid
	// user-info, we are not really "using" the user-info yet
	err = json.Unmarshal(body, &data)
	if err != nil {
		result.Result = "Error parsing json"
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	result.Gateways = tenant.Gateways
	utils.WriteResult(w, result)

	glog.Info("User ", data.User, " tenant ", tenant, " device ", device, " signed in")
}
