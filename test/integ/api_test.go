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

type Gateway_v1 struct {
	Name string `json:"name" bson:"name"`
	Zone string `json:"zone" bson:"zone"`
}

func addGateway(gw *Gateway_v1) bool {
	body, err := json.Marshal(gw)
	if err != nil {
		return false
	}

	resp, err := http.Post("http://127.0.0.1:8080/api/v1/addgateway", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	var data router.AddgatewayResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		return false
	}
	if data.Result != "ok" {
		return false
	}

	dbGw := db.DBFindGateway(gw.Name)
	if dbGw == nil {
		return false
	}

	return true
}
func TestGatewayAdd_v1(t *testing.T) {
	db.DBReinit()
	gw := Gateway_v1{Name: "sjc.nextensio.net", Zone: "us-west"}
	add := addGateway(&gw)
	if add == false {
		t.Error()
		return
	}
}

type Tenant_v1 struct {
	Uuid     string   `json:"uuid" bson:"uuid"`
	Idp      string   `json:"idp" bson:"idp"`
	Gateways []string `json:"gateways"`
}

func addTenant(tenant *Tenant_v1) bool {
	body, err := json.Marshal(tenant)
	if err != nil {
		return false
	}
	resp, err := http.Post("http://127.0.0.1:8080/api/v1/addtenant", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	var data router.AddtenantResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		return false
	}
	if data.Result != "ok" {
		return false
	}

	dbTenant := db.DBFindTenant(tenant.Uuid)
	if dbTenant == nil {
		return false
	}

	return true
}

func TestAddTenant(t *testing.T) {
	db.DBReinit()

	var tenant = Tenant_v1{Uuid: "foobar", Idp: "http://127.0.0.1:8081/test/api/v1",
		Gateways: []string{"sjc.nextensio.net", "ric.nextensio.net"},
	}
	add := addTenant(&tenant)
	if add == true {
		// The above add should NOT succeed because we have not added any gateways yet
		t.Error()
		return
	}

	// add one gateway, but the tenant add should still fail since only one is added yet
	gw := Gateway_v1{Name: "sjc.nextensio.net", Zone: "us-west"}
	add = addGateway(&gw)
	if add == false {
		t.Error()
		return
	}

	add = addTenant(&tenant)
	if add == true {
		// The above add should NOT succeed because we have not added second gateway yet
		t.Error()
		return
	}

	gw = Gateway_v1{Name: "ric.nextensio.net", Zone: "us-west"}
	add = addGateway(&gw)
	if add == false {
		t.Error()
		return
	}
	add = addTenant(&tenant)
	if add == false {
		// Now that both gateways are added, tenant added should succeed
		t.Error()
		return
	}
}

func TestOnboard(t *testing.T) {
	// add one gateway, but the tenant add should still fail since only one is added yet
	gw := Gateway_v1{Name: "sjc.nextensio.net", Zone: "us-west"}
	add := addGateway(&gw)
	if add == false {
		t.Error()
		return
	}
	gw = Gateway_v1{Name: "ric.nextensio.net", Zone: "us-west"}
	add = addGateway(&gw)
	if add == false {
		t.Error()
		return
	}
	var tenant = Tenant_v1{Uuid: "foobar", Idp: "http://127.0.0.1:8081/test/api/v1",
		Gateways: []string{"sjc.nextensio.net", "ric.nextensio.net"},
	}
	add = addTenant(&tenant)
	if add == false {
		// The above add should NOT succeed because we have not added any gateways yet
		t.Error()
		return
	}

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/onboard/ABCD/abcd/foobar")
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
	var data router.OnboardResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}
	if len(data.Gateways) != 2 {
		t.Error()
		return
	}
	if data.Gateways[0] != "sjc.nextensio.net" {
		t.Error()
		return
	}
	if data.Gateways[1] != "ric.nextensio.net" {
		t.Error()
		return
	}
}
