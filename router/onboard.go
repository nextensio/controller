package router

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"nextensio/controller/db"
	"nextensio/controller/utils"
	"time"

	"github.com/golang/glog"
	"github.com/gorilla/mux"
)

func rdonlyOnboard() {
	// This route is used by the agent while onboarding, agent presents access-token, device-id and
	// tenant-id and expects to get information like the gateway in response
	addRoute("/api/v1/onboard/{tenant-uuid}/{device-id}/{access-token}", "GET", onboardHandler)

	// This route is used to get basic user info
	addRoute("/api/v1/getuser/{tenant-uuid}/{userid}", "GET", getuserHandler)

	// This route is used to get user attributes that decide the policies applied to the user etc.
	addRoute("/api/v1/getuserattr/{tenant-uuid}/{userid}", "GET", getuserAttrHandler)

	// This route is used to get basic application info
	addRoute("/api/v1/getbundle/{tenant-uuid}/{bid}", "GET", getbundleHandler)

	// This route is used to get application attributes that are used with OPA.
	addRoute("/api/v1/getbundleattr/{tenant-uuid}/{bid}", "GET", getbundleAttrHandler)
}

func rdwrOnboard() {
	// This route is used by the controller admin to addd a new tenant
	addRoute("/api/v1/addtenant", "POST", addtenantHandler)

	// This route is used to add new gateways, gateways can be multi-tenant
	addRoute("/api/v1/addgateway", "POST", addgatewayHandler)

	// This route is used to add new users with basic user info
	addRoute("/api/v1/adduser", "POST", adduserHandler)

	// This route is used to add attributes that decide the policies applied to the user etc.
	addRoute("/api/v1/adduserattr", "POST", adduserAttrHandler)

	// This route is used to add new applications with basic application info
	addRoute("/api/v1/addbundle", "POST", addbundleHandler)

	// This route is used to add app attributes that are used with OPA policies.
	addRoute("/api/v1/addbundleattr", "POST", addbundleAttrHandler)
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

type AdduserResult struct {
	Result string `json:"Result"`
}

// Add a new user, with basic information that identifies the user
func adduserHandler(w http.ResponseWriter, r *http.Request) {
	var result AdduserResult
	var data db.User

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
	err = db.DBAddUser(&data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type AdduserAttrResult struct {
	Result string `json:"Result"`
}

// Add a user's attributes, used to decide what policies are applied to the user etc.
func adduserAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result AdduserAttrResult
	var data db.UserAttr

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
	err = db.DBAddUserAttr(&data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type GetuserResult struct {
	Result string `json:"Result"`
	db.User
}

// Get an OPA policy
func getuserHandler(w http.ResponseWriter, r *http.Request) {
	var result GetuserResult

	v := mux.Vars(r)
	uuid := v["tenant-uuid"]
	userid := v["userid"]
	user := db.DBFindUser(uuid, userid)
	if user == nil {
		result.Result = "Cannot find user"
	} else {
		result = GetuserResult{Result: "ok", User: *user}
	}
	utils.WriteResult(w, result)
}

type GetuserAttrResult struct {
	Result string `json:"Result"`
	db.UserAttr
}

// Get an OPA policy
func getuserAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result GetuserAttrResult

	v := mux.Vars(r)
	uuid := v["tenant-uuid"]
	userid := v["userid"]
	attr := db.DBFindUserAttr(uuid, userid)
	if attr == nil {
		result.Result = "Cannot find user attributes"
	} else {
		result = GetuserAttrResult{Result: "ok", UserAttr: *attr}
	}
	utils.WriteResult(w, result)
}

type AddBundleResult struct {
	Result string `json:"Result"`
}

// Add a new user, with basic information that identifies the user
func addbundleHandler(w http.ResponseWriter, r *http.Request) {
	var result AddBundleResult
	var data db.Bundle

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
	err = db.DBAddBundle(&data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type AddbundleAttrResult struct {
	Result string `json:"Result"`
}

// Add a user's attributes, used to decide what policies are applied to the user etc.
func addbundleAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result AddbundleAttrResult
	var data db.BundleAttr

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
	err = db.DBAddBundleAttr(&data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type GetbundleResult struct {
	Result string `json:"Result"`
	db.Bundle
}

// Get an OPA policy
func getbundleHandler(w http.ResponseWriter, r *http.Request) {
	var result GetbundleResult

	v := mux.Vars(r)
	uuid := v["tenant-uuid"]
	bid := v["bid"]
	bundle := db.DBFindBundle(uuid, bid)
	if bundle == nil {
		result.Result = "Cannot find user"
	} else {
		result = GetbundleResult{Result: "ok", Bundle: *bundle}
	}
	utils.WriteResult(w, result)
}

type GetbundleAttrResult struct {
	Result string `json:"Result"`
	db.BundleAttr
}

// Get an OPA policy
func getbundleAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result GetbundleAttrResult

	v := mux.Vars(r)
	uuid := v["tenant-uuid"]
	bid := v["bid"]
	attr := db.DBFindBundleAttr(uuid, bid)
	if attr == nil {
		result.Result = "Cannot find user attributes"
	} else {
		result = GetbundleAttrResult{Result: "ok", BundleAttr: *attr}
	}
	utils.WriteResult(w, result)
}
