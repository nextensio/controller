package router

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"nextensio/controller/db"
	"nextensio/controller/utils"

	"github.com/gorilla/mux"
)

func rdonlyPolicy() {
	// This route is used to retrieve a policy in a tenant
	addRoute("/api/v1/getpolicy/{tenant-uuid}/{policy-id}", "GET", getpolicyHandler)
}

func rdwrPolicy() {
	// This route is used by the controller admin to addd a new OPA policy to the tenant
	addRoute("/api/v1/addpolicy", "POST", addpolicyHandler)
}

type AddpolicyResult struct {
	Result string `json:"Result"`
}

// Add a new OPA policy
func addpolicyHandler(w http.ResponseWriter, r *http.Request) {
	var result AddpolicyResult
	var data db.Policy

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
	err = db.DBAddPolicy(&data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type GetpolicyResult struct {
	Result string `json:"Result"`
	db.Policy
}

// Get an OPA policy
func getpolicyHandler(w http.ResponseWriter, r *http.Request) {
	var result GetpolicyResult

	v := mux.Vars(r)
	uuid := v["tenant-uuid"]
	pid := v["policy-id"]
	policy := db.DBFindPolicy(uuid, pid)
	if policy == nil {
		result.Result = "Cannot find policy"
	} else {
		result = GetpolicyResult{Result: "ok", Policy: *policy}
	}
	utils.WriteResult(w, result)
}
