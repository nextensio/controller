package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"nextensio/controller/db"
	"nextensio/controller/router"
	"testing"
)

type Policy_v1 struct {
	PolicyId string `json:"pid" bson:"_id"`
	Rego     []rune `json:"rego" bson:"rego"`
}

func PolicyAdd_v1(t *testing.T, addtenant bool, pid string) {
	if addtenant {
		AddTenant_v1(t)
	}
	dbTenants := db.DBFindAllTenants()

	policy := Policy_v1{
		PolicyId: pid,
		Rego:     []rune("some-json-policy-here"),
	}
	body, err := json.Marshal(policy)
	if err != nil {
		t.Error()
		return
	}
	resp, err := http.Post("http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/add/policy", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Error()
		return
	}
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error()
		return
	}
	var data router.AddpolicyResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}

	dbPolicy := db.DBFindPolicy(dbTenants[0].ID, policy.PolicyId)
	if dbPolicy == nil {
		t.Error()
		return
	}
}

func TestPolicyAdd_v1(t *testing.T) {
	db.DBReinit()
	PolicyAdd_v1(t, true, "agent-authorization")
}

func TestPolicyGet_v1(t *testing.T) {
	db.DBReinit()
	PolicyAdd_v1(t, true, "agent-authorization")
	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/tenant/" + dbTenants[0].ID + "/get/policy/agent-authorization")
	if err != nil {
		t.Error()
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error()
		return
	}
	var data router.GetpolicyResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}
	if string(data.Rego) != "some-json-policy-here" {
		t.Error()
		return
	}
}

func TestGetAllPolicies_v1(t *testing.T) {
	db.DBReinit()

	PolicyAdd_v1(t, true, "agent-authorization")
	PolicyAdd_v1(t, false, "agent-access")

	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/tenant/" + dbTenants[0].ID + "/get/allpolicies")
	if err != nil {
		t.Error()
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error()
		return
	}
	var data []db.Policy
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if len(data) != 2 {
		t.Error()
		return
	}
	found := 0
	for i := 0; i < len(data); i++ {
		if data[i].PolicyId == "agent-authorization" {
			found++
		}
		if data[i].PolicyId == "agent-access" {
			found++
		}
	}
	if found != 2 {
		t.Error()
		return
	}
}

func PolicyDel_v1(t *testing.T, name string) {
	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/tenant/" + dbTenants[0].ID + "/del/policy/" + name)
	if err != nil {
		t.Error()
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error()
		return
	}
	var data router.DelpolicyResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}
	if db.DBFindAllPolicies(dbTenants[0].ID) != nil {
		t.Error()
		return
	}
}

func TestPolicyDel_v1(t *testing.T) {
	db.DBReinit()
	PolicyAdd_v1(t, true, "agent-authorization")
	PolicyDel_v1(t, "agent-authorization")
}
