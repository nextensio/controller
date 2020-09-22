package router

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"nextensio/controller/db"
	"nextensio/controller/utils"

	"github.com/gorilla/mux"
)

func rdonlyPolicy() {
	// This route is used to retrieve a policy in a tenant
	addRoute("/api/v1/getpolicy/{tenant-uuid}/{policy-id}", "GET", getpolicyHandler)

	// This route is used to get all policies
	addRoute("/api/v1/getallpolicies/{tenant-uuid}", "GET", getAllPoliciesHandler)
}

func rdwrPolicy() {
	// This route is used by the controller admin to addd a new OPA policy to the tenant
	addRoute("/api/v1/addpolicy", "POST", addpolicyHandler)

	// This route is used by the controller admin to delete an OPA policy
	addRoute("/api/v1/delpolicy/{tenant-uuid}/{policy-id}", "GET", delpolicyHandler)
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
		fmt.Println(err)
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
	pid := v["policy-id"]
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Bad tenant id"
		utils.WriteResult(w, result)
		return
	}

	policy := db.DBFindPolicy(uuid, pid)
	if policy == nil {
		result.Result = "Cannot find policy"
	} else {
		result = GetpolicyResult{Result: "ok", Policy: *policy}
	}
	utils.WriteResult(w, result)
}

// Get all policies
func getAllPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		utils.WriteResult(w, make([]db.Policy, 0))
		return
	}

	policies := db.DBFindAllPolicies(uuid)
	if policies == nil {
		policies = make([]db.Policy, 0)
	}
	utils.WriteResult(w, policies)

}

type DelpolicyResult struct {
	Result string `json:"Result"`
}

// Delete an OPA policy
func delpolicyHandler(w http.ResponseWriter, r *http.Request) {
	var result DelpolicyResult

	v := mux.Vars(r)
	pid := v["policy-id"]
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Bad tenant id"
		utils.WriteResult(w, result)
		return
	}

	err = db.DBDelPolicy(uuid, pid)
	if err != nil {
		result.Result = err.Error()
	} else {
		result = DelpolicyResult{Result: "ok"}
	}
	utils.WriteResult(w, result)
}
