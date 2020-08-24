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
	Uuid     string `json:"uuid" bson:"uuid"`
	PolicyId string `json:"pid" bson:"pid"`
	Version  uint   `json:"version" bson:"version"`
	OPA      string `json:"policy" bson:"policy"`
}

func TestPolicyAdd_v1(t *testing.T) {
	TestAddTenant_v1(t)

	policy := Policy_v1{
		Uuid:     "foobar",
		PolicyId: "agent-authorization",
		Version:  1,
		OPA:      "some-json-policy-here",
	}
	body, err := json.Marshal(policy)
	if err != nil {
		t.Error()
		return
	}
	resp, err := http.Post("http://127.0.0.1:8080/api/v1/addpolicy", "application/json", bytes.NewBuffer(body))
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

	dbTenant := db.DBFindPolicy(policy.Uuid, policy.PolicyId)
	if dbTenant == nil {
		t.Error()
		return
	}
}

func TestPolicyGet_v1(t *testing.T) {
	TestPolicyAdd_v1(t)

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/getpolicy/foobar/agent-authorization")
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
	if data.OPA != "some-json-policy-here" {
		t.Error()
		return
	}
}
