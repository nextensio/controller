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

func testGatewayAdd_v1(t *testing.T) {
	gw := Gateway_v1{Name: "sjc.nextensio.net", Zone: "us-west"}
	add := addGateway(&gw)
	if add == false {
		t.Error()
		return
	}
}

func TestGatewayAdd_v1(t *testing.T) {
	db.DBReinit()
	testGatewayAdd_v1(t)
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

func testAddTenant_v1(t *testing.T) {
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

func TestAddTenant_v1(t *testing.T) {
	db.DBReinit()
	testAddTenant_v1(t)
}

func addGatewayAndTenant(t *testing.T) {
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
}

func TestOnboard_v1(t *testing.T) {
	db.DBReinit()

	addGatewayAndTenant(t)

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/onboard/foobar/ABCD/abcd")
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

type User_v1 struct {
	Tenant string `json:"tenant" bson:"tenant"`
	Userid string `json:"userid" bson:"userid"`
	Name   string `json:"name" bson:"name"`
	Email  string `json:"email" bson:"email"`
}

func testUserAdd_v1(t *testing.T) {
	testAddTenant_v1(t)

	user := User_v1{
		Tenant: "foobar",
		Userid: "gopa",
		Name:   "Gopa Kumar",
		Email:  "gopa@nextensio.net",
	}
	body, err := json.Marshal(user)
	if err != nil {
		t.Error()
		return
	}
	resp, err := http.Post("http://127.0.0.1:8080/api/v1/adduser", "application/json", bytes.NewBuffer(body))
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
	var data router.AdduserResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}

	dbUser := db.DBFindUser(user.Tenant, user.Userid)
	if dbUser == nil {
		t.Error()
		return
	}
}

func TestUserAdd_v1(t *testing.T) {
	db.DBReinit()
	testUserAdd_v1(t)
}

func TestUserGet_v1(t *testing.T) {
	db.DBReinit()
	testUserAdd_v1(t)

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/getuser/foobar/gopa")
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
	var data router.GetuserResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}
	if data.Username != "Gopa Kumar" {
		t.Error()
		return
	}
}

type UserAttr_v1 struct {
	Userid   string   `bson:"userid" json:"userid"`
	Tenant   string   `bson:"tenant" json:"tenant"`
	Majver   string   `bson:"majver" json:"maj_ver"`
	Minver   string   `bson:"minver" json:"min_ver"`
	Category string   `bson:"category" json:"category"`
	Type     string   `bson:"type" json:"type"`
	Level    string   `bson:"level" json:"level"`
	Dept     []string `bson:"dept" json:"dept"`
	Team     []string `bson:"team" json:"team"`
}

func testUserAttrAdd_v1(t *testing.T) {
	db.DBReinit()
	testUserAdd_v1(t)

	attr := UserAttr_v1{
		Userid:   "gopa",
		Tenant:   "foobar",
		Majver:   "1",
		Minver:   "0",
		Category: "TODO",
		Type:     "TODO",
		Level:    "IC",
		Dept:     []string{"engineering", "marketing"},
		Team:     []string{"Engineering"},
	}
	body, err := json.Marshal(attr)
	if err != nil {
		t.Error()
		return
	}
	resp, err := http.Post("http://127.0.0.1:8080/api/v1/adduserattr", "application/json", bytes.NewBuffer(body))
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
	var data router.AdduserAttrResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}

	dbAttr := db.DBFindUserAttr(attr.Tenant, attr.Userid)
	if dbAttr == nil {
		t.Error()
		return
	}
	if len(dbAttr.Dept) != 2 {
		t.Error()
		return
	}
	if dbAttr.Dept[0] != "engineering" || dbAttr.Dept[1] != "marketing" {
		t.Error()
		return
	}
}
func TestUserAttrAdd_v1(t *testing.T) {
	db.DBReinit()
	testUserAttrAdd_v1(t)
}

func TestUserAttrGet_v1(t *testing.T) {
	db.DBReinit()
	testUserAttrAdd_v1(t)

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/getuserattr/foobar/gopa")
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
	var data router.GetuserAttrResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}

	if len(data.Dept) != 2 {
		t.Error()
		return
	}
	if data.Dept[0] != "engineering" || data.Dept[1] != "marketing" {
		t.Error()
		return
	}
}

type Bundle_v1 struct {
	Bid        string `json:"bid" bson:"bid"`
	Tenant     string `json:"tenant" bson:"tenant"`
	Bundlename string `json:"name" bson:"name"`
}

func testBundleAdd_v1(t *testing.T) {
	testAddTenant_v1(t)

	user := Bundle_v1{
		Bid:        "youtube",
		Tenant:     "foobar",
		Bundlename: "Google Youtube service",
	}
	body, err := json.Marshal(user)
	if err != nil {
		t.Error()
		return
	}
	resp, err := http.Post("http://127.0.0.1:8080/api/v1/addbundle", "application/json", bytes.NewBuffer(body))
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
	var data router.AddBundleResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}

	dbBundle := db.DBFindBundle(user.Tenant, user.Bid)
	if dbBundle == nil {
		t.Error()
		return
	}
}

func TestBundleAdd_v1(t *testing.T) {
	db.DBReinit()
	testBundleAdd_v1(t)
}

func TestBundleGet_v1(t *testing.T) {
	db.DBReinit()
	testBundleAdd_v1(t)

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/getbundle/foobar/youtube")
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
	var data router.GetbundleResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}
	if data.Bid != "youtube" {
		t.Error()
		return
	}
}

type BundleAttr_v1 struct {
	Bid         string   `bson:"bid" json:"bid"`
	Tenant      string   `bson:"tenant" json:"tenant"`
	Majver      string   `bson:"majver" json:"maj_ver"`
	Minver      string   `bson:"minver" json:"min_ver"`
	Team        []string `bson:"team" json:"team"`
	Dept        []string `bson:"dept" json:"dept"`
	Contrib     string   `bson:"IC" json:"IC"`
	Manager     string   `bson:"manager" json:"manager"`
	Nonemployee string   `bson:"nonemployee" json:"nonemployee"`
}

func testBundleAttrAdd_v1(t *testing.T) {
	db.DBReinit()
	testBundleAdd_v1(t)

	attr := BundleAttr_v1{
		Bid:         "youtube",
		Tenant:      "foobar",
		Majver:      "1",
		Minver:      "0",
		Team:        []string{"TODO"},
		Dept:        []string{"guest"},
		Contrib:     "TODO",
		Manager:     "TODO",
		Nonemployee: "TODO",
	}
	body, err := json.Marshal(attr)
	if err != nil {
		t.Error()
		return
	}
	resp, err := http.Post("http://127.0.0.1:8080/api/v1/addbundleattr", "application/json", bytes.NewBuffer(body))
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
	var data router.AddbundleAttrResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}

	dbAttr := db.DBFindBundleAttr(attr.Tenant, attr.Bid)
	if dbAttr == nil {
		t.Error()
		return
	}
	if len(dbAttr.Dept) != 1 {
		t.Error()
		return
	}
	if dbAttr.Dept[0] != "guest" {
		t.Error()
		return
	}
}
func TestBundleAttrAdd_v1(t *testing.T) {
	db.DBReinit()
	testBundleAttrAdd_v1(t)
}

func TestBundleAttrGet_v1(t *testing.T) {
	db.DBReinit()
	testBundleAttrAdd_v1(t)

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/getbundleattr/foobar/youtube")
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
	var data router.GetbundleAttrResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}

	if len(data.Dept) != 1 {
		t.Error()
		return
	}
	if data.Dept[0] != "guest" {
		t.Error()
		return
	}
}
