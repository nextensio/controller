package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"nextensio/controller/db"
	"nextensio/controller/router"
	"testing"
)

type Gateway_v1 struct {
	Name string `json:"name" bson:"_id"`
}

func addGateway(gw *Gateway_v1) bool {
	body, err := json.Marshal(gw)
	if err != nil {
		return false
	}

	resp, err := http.Post("http://127.0.0.1:8080/api/v1/addgateway", "application/json", bytes.NewBuffer(body))
	if err != nil {
		fmt.Println("Add gw failed")
		return false
	}
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	var data router.OpResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		fmt.Println("unmarshall failed")
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
	gw := Gateway_v1{Name: "sjc.nextensio.net"}
	add := addGateway(&gw)
	if add == false {
		t.Error()
		return
	}
}

func TestAddGateway_v1(t *testing.T) {
	db.DBReinit()
	testGatewayAdd_v1(t)
}

func delGateway(gw *Gateway_v1) bool {
	body, err := json.Marshal(gw)
	if err != nil {
		return false
	}

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/delgateway/" + gw.Name)
	if err != nil {
		fmt.Println("Delete gw failed")
		return false
	}
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	var data router.OpResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		fmt.Println("unmarshall failed")
		return false
	}
	if data.Result != "ok" {
		return false
	}

	dbGw := db.DBFindGateway(gw.Name)
	if dbGw != nil {
		return false
	}

	return true
}

func TestDelGateway_v1(t *testing.T) {
	db.DBReinit()
	AddTenant_v1(t)
	gw := Gateway_v1{Name: "sjc.nextensio.net"}
	if delGateway(&gw) {
		// should not be able to delete gateway in use
		t.Error()
		return
	}
	gw = Gateway_v1{Name: "ric.nextensio.net"}
	if delGateway(&gw) {
		// should not be able to delete gateway in use
		t.Error()
		return
	}
	gw = Gateway_v1{Name: "abc.nextensio.net"}
	addGateway(&gw)
	if !delGateway(&gw) {
		t.Error()
		return
	}
}

func TestGetAllGateway_v1(t *testing.T) {
	db.DBReinit()
	gw := Gateway_v1{Name: "sjc.nextensio.net"}
	add := addGateway(&gw)
	if add == false {
		t.Error()
		return
	}
	gw = Gateway_v1{Name: "ric.nextensio.net"}
	add = addGateway(&gw)
	if add == false {
		t.Error()
		return
	}

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/getallgateways")
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
	var data []db.Gateway
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
		if data[i].Name == "sjc.nextensio.net" {
			found++
		}
		if data[i].Name == "ric.nextensio.net" {
			found++
		}
	}
	if found != 2 {
		t.Error()
		return
	}
}

type Tenant_v1 struct {
	ID       string   `json:"_id" bson:"_id"`
	Name     string   `json:"name" bson:"name"`
	Gateways []string `json:"gateways"`
	Domains  []string `json:"domains"`
	Image    string   `json:"image" bson:"image"`
	Pods     int      `json:"pods" bson:"pods"`
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
	var data router.OpResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		return false
	}
	if data.Result != "ok" {
		return false
	}

	found := false
	dbTenants := db.DBFindAllTenants()
	for i := 0; i < len(dbTenants); i++ {
		if dbTenants[i].Name == tenant.Name {
			found = true
		}
	}
	if !found {
		return false
	}

	found = false
	dbNamespaces := db.DBFindAllNamespaces()
	for i := 0; i < len(dbNamespaces); i++ {
		if dbNamespaces[i].Name == tenant.Name {
			found = true
		}
	}
	if !found {
		return false
	}

	return true
}

func AddTenant_v1(t *testing.T) {
	var tenant = Tenant_v1{Name: "foobar",
		Gateways: []string{"sjc.nextensio.net", "ric.nextensio.net"},
		Domains:  []string{"kismis.org"},
		Image:    "davigupta/minion:0.80",
		Pods:     10,
	}
	add := addTenant(&tenant)
	if add == true {
		// The above add should NOT succeed because we have not added any gateways yet
		t.Error()
		return
	}

	// add one gateway, but the tenant add should still fail since only one is added yet
	gw := Gateway_v1{Name: "sjc.nextensio.net"}
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

	gw = Gateway_v1{Name: "ric.nextensio.net"}
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
	AddTenant_v1(t)
}

func TestGetAllTenant_v1(t *testing.T) {
	db.DBReinit()

	// add one gateway, but the tenant add should still fail since only one is added yet
	gw := Gateway_v1{Name: "sjc.nextensio.net"}
	add := addGateway(&gw)
	if add == false {
		t.Error()
		return
	}
	gw = Gateway_v1{Name: "ric.nextensio.net"}
	add = addGateway(&gw)
	if add == false {
		t.Error()
		return
	}
	var tenant1 = Tenant_v1{
		Name:     "foobar",
		Gateways: []string{"sjc.nextensio.net", "ric.nextensio.net"},
		Domains:  []string{"kismis.org"},
	}
	add = addTenant(&tenant1)
	if add == false {
		// The above add should NOT succeed because we have not added any gateways yet
		t.Error()
		return
	}
	var tenant2 = Tenant_v1{Name: "gloobar",
		Gateways: []string{"sjc.nextensio.net", "ric.nextensio.net"}}
	add = addTenant(&tenant2)
	if add == false {
		// The above add should NOT succeed because we have not added any gateways yet
		t.Error()
		return
	}

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/getalltenants")
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
	var data []db.Tenant
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
		if data[i].Name == "foobar" {
			found++
		}
		if data[i].Name == "gloobar" {
			found++
		}
	}
	if found != 2 {
		t.Error()
		return
	}
}

func testTenantDel(t *testing.T, expect_delete bool) {
	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/deltenant/" + dbTenants[0].ID.Hex())
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
	var data router.OpResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if expect_delete {
		if data.Result != "ok" {
			t.Error()
			return
		}
		if db.DBFindAllUsers(dbTenants[0].ID) != nil || db.DBFindAllUserAttrs(dbTenants[0].ID) != nil ||
			db.DBFindAllBundles(dbTenants[0].ID) != nil || db.DBFindAllBundleAttrs(dbTenants[0].ID) != nil ||
			db.DBFindAllPolicies(dbTenants[0].ID) != nil || db.DBFindNamespace(dbTenants[0].ID) != nil {
			t.Error()
			return
		}
	} else {
		if data.Result == "ok" {
			t.Error()
			return
		}
		if db.DBFindAllUsers(dbTenants[0].ID) == nil && db.DBFindAllUserAttrs(dbTenants[0].ID) == nil &&
			db.DBFindAllBundles(dbTenants[0].ID) == nil && db.DBFindAllBundleAttrs(dbTenants[0].ID) == nil &&
			db.DBFindAllPolicies(dbTenants[0].ID) == nil {
			t.Error()
			return
		}
	}
}

func TestTenantDel(t *testing.T) {
	db.DBReinit()
	testUserAttrAdd_v1(t, true, "gopa")
	testBundleAttrAdd_v1(t, false, "youtube")
	PolicyAdd_v1(t, false, "agent-access")
	testTenantDel(t, false)
	testUserDel(t, "gopa")
	testTenantDel(t, false)
	testBundleDel(t, "youtube")
	testTenantDel(t, false)
	PolicyDel_v1(t, "agent-access")
	testTenantDel(t, true)
}

func addGatewayAndTenant(t *testing.T) {
	// add one gateway, but the tenant add should still fail since only one is added yet
	gw := Gateway_v1{Name: "sjc.nextensio.net"}
	add := addGateway(&gw)
	if add == false {
		t.Error()
		return
	}
	gw = Gateway_v1{Name: "ric.nextensio.net"}
	add = addGateway(&gw)
	if add == false {
		t.Error()
		return
	}
	var tenant = Tenant_v1{
		Name:     "foobar",
		Gateways: []string{"sjc.nextensio.net", "ric.nextensio.net"},
		Domains:  []string{"kismis.org"},
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
	UserAdd_v1(t, false, "abcd", []string{})
	CertAdd_v1(t, "CACert")
	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/onboard/abcd_" + dbTenants[0].ID.Hex())
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
	if len(data.Domains) != 1 {
		t.Error()
		return
	}
	if data.Domains[0] != "kismis.org" {
		t.Error()
		return
	}
	if data.Gateway != "sjc.nextensio.net" && data.Gateway != "ric.nextensio.net" {
		t.Error()
		return
	}
}

type User_v1 struct {
	Uid       string   `json:"uid" bson:"_id"`
	Tenant    string   `json:"tenant" bson:"tenant"`
	Name      string   `json:"name" bson:"name"`
	Email     string   `json:"email" bson:"email"`
	Gateway   string   `json:"gateway" bson:"gateway"`
	Pod       int      `json:"pod" bson:"pod"`
	Connectid string   `json:"connectid" bson:"connectid"`
	Services  []string `json:"services" bson:"services"`
}

func UserAdd_v1(t *testing.T, tenantadd bool, userid string, services []string) {
	if tenantadd {
		AddTenant_v1(t)
	}
	dbTenants := db.DBFindAllTenants()

	user := User_v1{
		Tenant:    dbTenants[0].ID.Hex(),
		Uid:       userid,
		Name:      "Gopa Kumar",
		Email:     "gopa@nextensio.net",
		Gateway:   "",
		Pod:       1,
		Connectid: "unused",
		Services:  services,
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
	var data router.OpResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}

	dbUser := db.DBFindUser(dbTenants[0].ID, user.Uid)
	if dbUser == nil {
		t.Error()
		return
	}
	clUser := db.DBFindClusterUser(dbTenants[0].ID, user.Uid)
	if clUser == nil {
		t.Error()
		return
	}
}

func TestUserAdd_v1(t *testing.T) {
	db.DBReinit()
	UserAdd_v1(t, true, "gopa", []string{})
}

func TestUserGet_v1(t *testing.T) {
	db.DBReinit()
	UserAdd_v1(t, true, "gopa", []string{})
	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/getuser/" + dbTenants[0].ID.Hex() + "/gopa")
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
	if data.User.Username != "Gopa Kumar" {
		t.Error()
		return
	}
}

func TestGetAllUsers_v1(t *testing.T) {
	db.DBReinit()

	UserAdd_v1(t, true, "gopa", []string{})
	UserAdd_v1(t, false, "kumar", []string{})

	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/getallusers/" + dbTenants[0].ID.Hex())
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
	var data []db.User
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
		if data[i].Uid == "gopa" {
			found++
		}
		if data[i].Uid == "kumar" {
			found++
		}
	}
	if found != 2 {
		t.Error()
		return
	}
}

type UserAttrHdr_v1 struct {
	Tenant string `bson:"tenant" json:"tenant"`
	Majver int    `bson:"majver" json:"majver"`
	Minver int    `bson:"minver" json:"minver"`
}

func testUserAttrHdrAdd_v1(t *testing.T) {
	// Just to get a user collection created
	UserAdd_v1(t, true, "some-user", []string{})
	dbTenants := db.DBFindAllTenants()

	attr := UserAttrHdr_v1{
		Tenant: dbTenants[0].ID.Hex(),
		Majver: 2,
		Minver: 1,
	}
	body, err := json.Marshal(attr)
	if err != nil {
		t.Error()
		return
	}
	resp, err := http.Post("http://127.0.0.1:8080/api/v1/adduserattrhdr", "application/json", bytes.NewBuffer(body))
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
	var data router.OpResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}

	dbHdr := db.DBFindUserAttrHdr(dbTenants[0].ID)
	if dbHdr == nil {
		t.Error()
		return
	}
	if dbHdr.Majver != 2 {
		t.Error()
		return
	}
	if dbHdr.Minver != 1 {
		t.Error()
		return
	}
}
func TestUserAttrHdrAdd_v1(t *testing.T) {
	db.DBReinit()
	testUserAttrHdrAdd_v1(t)
}

func TestAttrHdrGet_v1(t *testing.T) {
	db.DBReinit()
	testUserAttrHdrAdd_v1(t)
	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/getuserattrhdr/" + dbTenants[0].ID.Hex())
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
	var data []db.DataHdr
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if len(data) != 1 {
		t.Error()
		return
	}
	if data[0].Majver != 2 {
		t.Error()
		return
	}
	if data[0].Minver != 1 {
		t.Error()
		return
	}
}

type UserAttr_v1 struct {
	Uid      string   `bson:"_id" json:"uid"`
	Tenant   string   `bson:"tenant" json:"tenant"`
	Category string   `bson:"category" json:"category"`
	Type     string   `bson:"type" json:"type"`
	Level    int      `bson:"level" json:"level"`
	Dept     []string `bson:"dept" json:"dept"`
	Team     []string `bson:"team" json:"team"`
}

func testUserAttrAdd_v1(t *testing.T, tenantadd bool, userid string) {
	UserAdd_v1(t, tenantadd, userid, []string{})
	dbTenants := db.DBFindAllTenants()

	attr := UserAttr_v1{
		Uid:      userid,
		Tenant:   dbTenants[0].ID.Hex(),
		Category: "employee",
		Type:     "IC",
		Level:    2,
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
	var data router.OpResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}

	dbBson := db.DBFindUserAttr(dbTenants[0].ID, attr.Uid)
	if dbBson == nil {
		t.Error()
		return
	}
	dbJson, jerr := json.Marshal(&dbBson)
	if jerr != nil {
		t.Error()
		return
	}
	var dbAttr UserAttr_v1
	err = json.Unmarshal(dbJson, &dbAttr)
	if err != nil {
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
	testUserAttrAdd_v1(t, true, "gopa")
}

func TestUserAttrGet_v1(t *testing.T) {
	db.DBReinit()
	testUserAttrAdd_v1(t, true, "gopa")
	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/getuserattr/" + dbTenants[0].ID.Hex() + "/gopa")
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
	dbJson, jerr := json.Marshal(&data.UAttr)
	if jerr != nil {
		t.Error()
		return
	}
	var dbAttr UserAttr_v1
	err = json.Unmarshal(dbJson, &dbAttr)
	if err != nil {
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

func TestGetAllUserAttr_v1(t *testing.T) {
	db.DBReinit()

	testUserAttrAdd_v1(t, true, "gopa")
	testUserAttrAdd_v1(t, false, "kumar")

	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/getalluserattr/" + dbTenants[0].ID.Hex())
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
	var data []UserAttr_v1
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	// Two plus one for the attribute header
	if len(data) != 3 {
		t.Error()
		return
	}
	found := 0
	for i := 0; i < len(data); i++ {
		if data[i].Uid == "gopa" {
			found++
		}
		if data[i].Uid == "kumar" {
			found++
		}
	}
	if found != 2 {
		t.Error()
		return
	}
}

func testUserDel(t *testing.T, user string) {
	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/deluser/" + dbTenants[0].ID.Hex() + "/" + user)
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
	var data router.OpResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}
	if db.DBFindUser(dbTenants[0].ID, user) != nil || db.DBFindUserAttr(dbTenants[0].ID, user) != nil ||
		db.DBFindClusterUser(dbTenants[0].ID, user) != nil {
		t.Error()
		return
	}
}

func TestUserDel(t *testing.T) {
	db.DBReinit()
	testUserAttrAdd_v1(t, true, "gopa")
	testUserDel(t, "gopa")
}

type Bundle_v1 struct {
	Bid        string   `json:"bid" bson:"_id"`
	Tenant     string   `json:"tenant" bson:"tenant"`
	Bundlename string   `json:"name" bson:"name"`
	Gateway    string   `json:"gateway" bson:"gateway"`
	Pod        int      `json:"pod" bson:"pod"`
	Connectid  string   `json:"connectid" bson:"connectid"`
	Services   []string `json:"services" bson:"services"`
}

func testBundleAdd_v1(t *testing.T, tenantadd bool, bid string, services []string) {
	if tenantadd {
		AddTenant_v1(t)
	}
	dbTenants := db.DBFindAllTenants()

	user := Bundle_v1{
		Bid:        bid,
		Tenant:     dbTenants[0].ID.Hex(),
		Bundlename: "Google Youtube service",
		Gateway:    "",
		Pod:        1,
		Connectid:  "unused",
		Services:   services,
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
	var data router.OpResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}

	dbBundle := db.DBFindBundle(dbTenants[0].ID, user.Bid)
	if dbBundle == nil {
		t.Error()
		return
	}
	clUser := db.DBFindClusterUser(dbTenants[0].ID, user.Bid)
	if clUser == nil {
		t.Error()
		return
	}
}

func TestBundleAdd_v1(t *testing.T) {
	db.DBReinit()
	testBundleAdd_v1(t, true, "youtube", []string{})
}

func TestBundleGet_v1(t *testing.T) {
	db.DBReinit()
	testBundleAdd_v1(t, true, "youtube", []string{})
	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/getbundle/" + dbTenants[0].ID.Hex() + "/youtube")
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
	if data.Bundle.Bid != "youtube" {
		t.Error()
		return
	}
}

func TestGetAllBundles_v1(t *testing.T) {
	db.DBReinit()

	testBundleAdd_v1(t, true, "youtube", []string{})
	testBundleAdd_v1(t, false, "netflix", []string{})

	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/getallbundles/" + dbTenants[0].ID.Hex())
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
	var data []db.Bundle
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
		if data[i].Bid == "youtube" {
			found++
		}
		if data[i].Bid == "netflix" {
			found++
		}
	}
	if found != 2 {
		t.Error()
		return
	}
}

type BundleAttrHdr_v1 struct {
	Tenant string `bson:"tenant" json:"tenant"`
	Majver int    `bson:"majver" json:"majver"`
	Minver int    `bson:"minver" json:"minver"`
}

func testBundleAttrHdrAdd_v1(t *testing.T) {
	// Just to get a bundle collection created
	testBundleAdd_v1(t, true, "some-bundle", []string{})
	dbTenants := db.DBFindAllTenants()
	attr := BundleAttrHdr_v1{
		Tenant: dbTenants[0].ID.Hex(),
		Majver: 2,
		Minver: 1,
	}
	body, err := json.Marshal(attr)
	if err != nil {
		t.Error()
		return
	}
	resp, err := http.Post("http://127.0.0.1:8080/api/v1/addbundleattrhdr", "application/json", bytes.NewBuffer(body))
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
	var data router.OpResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}

	dbHdr := db.DBFindBundleAttrHdr(dbTenants[0].ID)
	if dbHdr == nil {
		t.Error()
		return
	}
	if dbHdr.Majver != 2 {
		t.Error()
		return
	}
	if dbHdr.Minver != 1 {
		t.Error()
		return
	}
}
func TestBundleAttrHdrAdd_v1(t *testing.T) {
	db.DBReinit()
	testBundleAttrHdrAdd_v1(t)
}

func TestBundleAttrHdrGet_v1(t *testing.T) {
	db.DBReinit()
	testBundleAttrHdrAdd_v1(t)
	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/getbundleattrhdr/" + dbTenants[0].ID.Hex())
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
	var data []db.DataHdr
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if len(data) != 1 {
		t.Error()
		return
	}
	if data[0].Majver != 2 {
		t.Error()
		return
	}
	if data[0].Minver != 1 {
		t.Error()
		return
	}
}

type BundleAttr_v1 struct {
	Bid         string   `bson:"_id" json:"bid"`
	Tenant      string   `bson:"tenant" json:"tenant"`
	Team        []string `bson:"team" json:"team"`
	Dept        []string `bson:"dept" json:"dept"`
	Contrib     int      `bson:"IC" json:"IC"`
	Manager     int      `bson:"manager" json:"manager"`
	Nonemployee string   `bson:"nonemployee" json:"nonemployee"`
}

func testBundleAttrAdd_v1(t *testing.T, tenantadd bool, bid string) {
	testBundleAdd_v1(t, tenantadd, bid, []string{})
	dbTenants := db.DBFindAllTenants()

	attr := BundleAttr_v1{
		Bid:         bid,
		Tenant:      dbTenants[0].ID.Hex(),
		Team:        []string{"TODO"},
		Dept:        []string{"guest"},
		Contrib:     1,
		Manager:     1,
		Nonemployee: "allowed",
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
	var data router.OpResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}

	dbBson := db.DBFindBundleAttr(dbTenants[0].ID, attr.Bid)
	if dbBson == nil {
		t.Error()
		return
	}
	dbJson, jerr := json.Marshal(&dbBson)
	if jerr != nil {
		t.Error()
		return
	}
	var dbAttr BundleAttr_v1
	err = json.Unmarshal(dbJson, &dbAttr)
	if err != nil {
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
	testBundleAttrAdd_v1(t, true, "youtube")
}

func TestBundleAttrGet_v1(t *testing.T) {
	db.DBReinit()
	testBundleAttrAdd_v1(t, true, "youtube")
	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/getbundleattr/" + dbTenants[0].ID.Hex() + "/youtube")
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
	dbJson, jerr := json.Marshal(&data.BAttr)
	if jerr != nil {
		t.Error()
		return
	}
	var dbAttr BundleAttr_v1
	err = json.Unmarshal(dbJson, &dbAttr)
	if err != nil {
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

func TestGetAllBundleAttr_v1(t *testing.T) {
	db.DBReinit()

	testBundleAttrAdd_v1(t, true, "youtube")
	testBundleAttrAdd_v1(t, false, "netflix")

	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/getallbundleattr/" + dbTenants[0].ID.Hex())
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
	var data []BundleAttr_v1
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	// Two plus one for the attribute header
	if len(data) != 3 {
		t.Error()
		return
	}
	found := 0
	for i := 0; i < len(data); i++ {
		if data[i].Bid == "youtube" {
			found++
		}
		if data[i].Bid == "netflix" {
			found++
		}
	}
	if found != 2 {
		t.Error()
		return
	}
}

func testBundleDel(t *testing.T, bundle string) {
	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/delbundle/" + dbTenants[0].ID.Hex() + "/" + bundle)
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
	var data router.OpResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}
	if db.DBFindBundle(dbTenants[0].ID, bundle) != nil || db.DBFindBundleAttr(dbTenants[0].ID, bundle) != nil ||
		db.DBFindClusterUser(dbTenants[0].ID, bundle) != nil {
		t.Error()
		return
	}
}

func TestBundleDel(t *testing.T) {
	db.DBReinit()
	testBundleAttrAdd_v1(t, true, "youtube")
	testBundleDel(t, "youtube")
}

func TestAgentServiceAdd_v1(t *testing.T) {
	db.DBReinit()
	UserAdd_v1(t, true, "gopa", []string{"a"})
	dbTenants := db.DBFindAllTenants()
	svc := db.DBFindClusterSvc(dbTenants[0].ID, "a")
	if svc == nil {
		t.Error()
		return
	}
	if svc.Agents[0] != "gopa" {
		t.Error()
		return
	}
	UserAdd_v1(t, false, "gopa", []string{"a", "b"})
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "a")
	if svc.Agents[0] != "gopa" {
		t.Error()
		return
	}
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "b")
	if svc.Agents[0] != "gopa" {
		t.Error()
		return
	}
	UserAdd_v1(t, false, "gopa", []string{"b", "c"})
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "a")
	if svc != nil {
		t.Error()
		return
	}
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "b")
	if svc.Agents[0] != "gopa" {
		t.Error()
		return
	}
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "c")
	if svc.Agents[0] != "gopa" {
		t.Error()
		return
	}
	UserAdd_v1(t, false, "gopa", []string{"c"})
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "a")
	if svc != nil {
		t.Error()
		return
	}
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "b")
	if svc != nil {
		t.Error()
		return
	}
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "c")
	if svc.Agents[0] != "gopa" {
		t.Error()
		return
	}
	UserAdd_v1(t, false, "kumar", []string{"c"})
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "c")
	if len(svc.Agents) != 2 {
		t.Error()
		return
	}
	if svc.Agents[0] != "gopa" && svc.Agents[1] != "gopa" {
		t.Error()
		return
	}
	if svc.Agents[0] != "kumar" && svc.Agents[1] != "kumar" {
		t.Error()
		return
	}
	UserAdd_v1(t, false, "gopa", []string{})
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "c")
	if len(svc.Agents) != 1 {
		t.Error()
		return
	}
	if svc.Agents[0] != "kumar" {
		t.Error()
		return
	}
}

func TestBundleServiceAdd_v1(t *testing.T) {
	db.DBReinit()
	testBundleAdd_v1(t, true, "gopa", []string{"a"})
	dbTenants := db.DBFindAllTenants()
	svc := db.DBFindClusterSvc(dbTenants[0].ID, "a")
	if svc == nil {
		t.Error()
		return
	}
	if svc.Agents[0] != "gopa" {
		t.Error()
		return
	}
	testBundleAdd_v1(t, false, "gopa", []string{"a", "b"})
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "a")
	if svc.Agents[0] != "gopa" {
		t.Error()
		return
	}
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "b")
	if svc.Agents[0] != "gopa" {
		t.Error()
		return
	}
	testBundleAdd_v1(t, false, "gopa", []string{"b", "c"})
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "a")
	if svc != nil {
		t.Error()
		return
	}
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "b")
	if svc.Agents[0] != "gopa" {
		t.Error()
		return
	}
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "c")
	if svc.Agents[0] != "gopa" {
		t.Error()
		return
	}
	testBundleAdd_v1(t, false, "gopa", []string{"c"})
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "a")
	if svc != nil {
		t.Error()
		return
	}
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "b")
	if svc != nil {
		t.Error()
		return
	}
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "c")
	if svc.Agents[0] != "gopa" {
		t.Error()
		return
	}
	testBundleAdd_v1(t, false, "kumar", []string{"c"})
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "c")
	if len(svc.Agents) != 2 {
		t.Error()
		return
	}
	if svc.Agents[0] != "gopa" && svc.Agents[1] != "gopa" {
		t.Error()
		return
	}
	if svc.Agents[0] != "kumar" && svc.Agents[1] != "kumar" {
		t.Error()
		return
	}
	testBundleAdd_v1(t, false, "gopa", []string{})
	svc = db.DBFindClusterSvc(dbTenants[0].ID, "c")
	if len(svc.Agents) != 1 {
		t.Error()
		return
	}
	if svc.Agents[0] != "kumar" {
		t.Error()
		return
	}
}

type Cert_v1 struct {
	Certid string `json:"certid" bson:"_id"`
	Cert   []rune `json:"cert" bson:"cert"`
}

func CertAdd_v1(t *testing.T, name string) {
	cert := Cert_v1{
		Certid: name,
		Cert:   []rune("some-certificate-here"),
	}
	body, err := json.Marshal(cert)
	if err != nil {
		t.Error()
		return
	}
	resp, err := http.Post("http://127.0.0.1:8080/api/v1/addcert", "application/json", bytes.NewBuffer(body))
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
	var data router.AddcertResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}

	dbCert := db.DBFindCert(cert.Certid)
	if dbCert == nil {
		t.Error()
		return
	}
	if string(dbCert.Cert) != "some-certificate-here" {
		t.Error()
		return
	}
}

func TestCertAdd_v1(t *testing.T) {
	db.DBReinit()
	CertAdd_v1(t, "rootCA")
}

func TestCertGet_v1(t *testing.T) {
	db.DBReinit()
	CertAdd_v1(t, "rootCA")

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/getcert/" + "rootCA")
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
	var data router.GetcertResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}
	if string(data.Cert) != "some-certificate-here" {
		t.Error()
		return
	}
}

func TestGetAllCerts_v1(t *testing.T) {
	db.DBReinit()

	CertAdd_v1(t, "rootCA")
	CertAdd_v1(t, "interCA")

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/getallcerts")
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
	var data []db.Certificate
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
		if data[i].Certid == "rootCA" {
			found++
		}
		if data[i].Certid == "interCA" {
			found++
		}
	}
	if found != 2 {
		t.Error()
		return
	}
}

func CertDel_v1(t *testing.T, name string) {
	resp, err := http.Get("http://127.0.0.1:8080/api/v1/delcert/" + name)
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
	var data router.DelcertResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}
	if db.DBFindAllCerts() != nil {
		t.Error()
		return
	}
}

func TestCertDel_v1(t *testing.T) {
	db.DBReinit()
	CertAdd_v1(t, "rootCA")
	CertDel_v1(t, "rootCA")
}