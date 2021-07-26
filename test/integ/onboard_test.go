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

// For unit testing, the access token is not validated, so contents dont matter
const AccessToken string = "contents-dont-matter"

var client = &http.Client{}

type Gateway_v1 struct {
	Name     string `json:"name" bson:"_id"`
	Location string `json:"location" bson:"location"`
	Zone     string `json:"zone" bson:"zone"`
	Region   string `json:"region" bson:"region"`
	Provider string `json:"provider" bson:"provider"`
}

func addGateway(gw *Gateway_v1) bool {
	body, err := json.Marshal(gw)
	if err != nil {
		return false
	}

	req, _ := http.NewRequest("POST", "http://127.0.0.1:8080/api/v1/global/add/gateway", bytes.NewBuffer(body))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

	_, dbGw := db.DBFindGateway(gw.Name)
	if dbGw == nil {
		return false
	}

	return true
}

func testGatewayAdd_v1(t *testing.T) {
	gw := Gateway_v1{Name: "sjc.nextensio.net", Location: "sjc"}
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

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/global/del/gateway/"+gw.Name, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

	_, dbGw := db.DBFindGateway(gw.Name)
	if dbGw != nil {
		return false
	}

	return true
}

func TestDelGateway_v1(t *testing.T) {
	db.DBReinit()
	AddTenant_v1(t)
	gw := Gateway_v1{Name: "sjc.nextensio.net", Location: "sjc"}
	if delGateway(&gw) {
		// should not be able to delete gateway in use
		t.Error()
		return
	}
	gw = Gateway_v1{Name: "ric.nextensio.net", Location: "ric"}
	if delGateway(&gw) {
		// should not be able to delete gateway in use
		t.Error()
		return
	}
	gw = Gateway_v1{Name: "abc.nextensio.net", Location: "abc"}
	addGateway(&gw)
	if !delGateway(&gw) {
		t.Error()
		return
	}
}

func TestGetAllGateway_v1(t *testing.T) {
	db.DBReinit()
	gw := Gateway_v1{Name: "sjc.nextensio.net", Location: "sjc"}
	add := addGateway(&gw)
	if add == false {
		t.Error()
		return
	}
	gw = Gateway_v1{Name: "ric.nextensio.net", Location: "ric"}
	add = addGateway(&gw)
	if add == false {
		t.Error()
		return
	}

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/global/get/allgateways", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
	ID      string   `json:"_id" bson:"_id"`
	Name    string   `json:"name" bson:"name"`
	Domains []string `json:"domains"`
}

type TenantCluster_v1 struct {
	Id      string `json:"id" bson: "_id"` // TenantID:ClusterId
	Gateway string `json:"gateway" bson:"gateway"`
	Image   string `json:"image" bson:"image"`
	Apods   int    `json:"apods" bson:"apods"`
	Cpods   int    `json:"cpods" bson:"cpods"`
}

func addTenant(tenant *Tenant_v1) bool {
	body, err := json.Marshal(tenant)
	if err != nil {
		return false
	}
	req, _ := http.NewRequest("POST", "http://127.0.0.1:8080/api/v1/global/add/tenant", bytes.NewBuffer(body))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

func addTenantCluster_v1(tenant string, tcl *TenantCluster_v1) bool {
	body, err := json.Marshal(tcl)
	if err != nil {
		return false
	}
	url := "http://127.0.0.1:8080/api/v1/tenant/" + tenant + "/add/tenantcluster"
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(body))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
	return true
}

func testTenantClusterDel(t *testing.T, cluster string) {
	dbTenants := db.DBFindAllTenants()

	cldoc := db.DBFindTenantCluster(dbTenants[0].ID, cluster)
	if cldoc == nil {
		t.Error()
		return
	}
	url := "http://127.0.0.1:8080/api/v1/tenant/" + dbTenants[0].ID + "/del/tenantcluster/" + cluster
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
	_, cl := db.DBFindClusterConfig(cluster, dbTenants[0].ID)
	if db.DBFindTenantCluster(dbTenants[0].ID, cluster) != nil ||
		cl != nil {
		t.Error()
		return
	}
}

// Add tenant, then add clusters sjc and ric, then assign tenant to both clusters.
// Each cluster has two pods.
func AddTenant_v1(t *testing.T) {
	var tenant = Tenant_v1{
		ID:      "nextensio",
		Name:    "foobar",
		Domains: []string{"kismis.org"},
	}
	add := addTenant(&tenant)
	if add == false {
		// The above add should succeed
		t.Error()
		return
	}

	tenants := db.DBFindAllTenants()
	if tenants == nil {
		t.Error()
		return
	}
	if len(tenants) > 1 {
		// We've added only one tenant
		t.Error()
		return
	}

	var tcluster1 = TenantCluster_v1{
		Id:      tenant.ID + ":sjc",
		Gateway: "sjc.nextensio.net",
		Image:   "",
		Apods:   1,
		Cpods:   1,
	}
	var tcluster2 = TenantCluster_v1{
		Id:      tenant.ID + ":ric",
		Gateway: "ric.nextensio.net",
		Image:   "",
		Apods:   1,
		Cpods:   1,
	}

	// Try to assign tenant to sjc cluster. Should fail since we haven't created sjc
	add = addTenantCluster_v1(tenant.ID, &tcluster1)
	if add == true {
		t.Error()
		return
	}

	// add gateway for sjc
	gw := Gateway_v1{Name: "sjc.nextensio.net", Location: "sjc"}
	add = addGateway(&gw)
	if add == false {
		t.Error()
		return
	}
	add = addTenantCluster_v1(tenant.ID, &tcluster1)
	if add == false {
		// The above add should have succeeded since sjc was added
		t.Error()
		return
	}

	add = addTenantCluster_v1(tenant.ID, &tcluster2)
	if add == true {
		// The above add should have failed since ric hasn't been created
		t.Error()
		return
	}

	gw = Gateway_v1{Name: "ric.nextensio.net", Location: "ric"}
	add = addGateway(&gw)
	if add == false {
		t.Error()
		return
	}
	add = addTenantCluster_v1(tenant.ID, &tcluster2)
	if add == false {
		// Now that ric is also added, tenant add to ric should succeed
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
	gw := Gateway_v1{Name: "sjc.nextensio.net", Location: "sjc"}
	add := addGateway(&gw)
	if add == false {
		t.Error()
		return
	}
	gw = Gateway_v1{Name: "ric.nextensio.net", Location: "ric"}
	add = addGateway(&gw)
	if add == false {
		t.Error()
		return
	}
	var tenant1 = Tenant_v1{
		ID:      "nextensio1",
		Name:    "foobar",
		Domains: []string{"kismis.org"},
	}
	add = addTenant(&tenant1)
	if add == false {
		// The above add should have succeeded
		t.Error()
		return
	}
	var tenant2 = Tenant_v1{
		ID:      "nextensio2",
		Name:    "gloobar",
		Domains: []string{"kismis.org"},
	}
	add = addTenant(&tenant2)
	if add == false {
		// The above add should have succeeded
		t.Error()
		return
	}

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/global/get/alltenants", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/global/del/tenant/"+dbTenants[0].ID, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
			t.Log(data.Result)
			t.Error()
			return
		}
		errCl, gws := db.DBTenantInAnyCluster(dbTenants[0].ID)
		if db.DBFindAllUsers(dbTenants[0].ID) != nil ||
			db.DBFindAllUserAttrs(dbTenants[0].ID) != nil ||
			db.DBFindAllBundles(dbTenants[0].ID) != nil ||
			db.DBFindAllBundleAttrs(dbTenants[0].ID) != nil ||
			db.DBFindAllPolicies(dbTenants[0].ID) != nil ||
			db.DBFindNamespace(dbTenants[0].ID) != nil ||
			errCl != nil || gws {
			t.Error()
			return
		}
	} else {
		if data.Result == "ok" {
			t.Error()
			return
		}
		errCl, gws := db.DBTenantInAnyCluster(dbTenants[0].ID)
		if db.DBFindAllUsers(dbTenants[0].ID) == nil &&
			db.DBFindAllUserAttrs(dbTenants[0].ID) == nil &&
			db.DBFindAllBundles(dbTenants[0].ID) == nil &&
			db.DBFindAllBundleAttrs(dbTenants[0].ID) == nil &&
			db.DBFindAllPolicies(dbTenants[0].ID) == nil &&
			errCl != nil || !gws {
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
	// add two gateways, add tenant, then assign tenant to both gateways
	gw := Gateway_v1{Name: "sjc.nextensio.net", Location: "sjc"}
	add := addGateway(&gw)
	if add == false {
		t.Error()
		return
	}
	gw = Gateway_v1{Name: "ric.nextensio.net", Location: "ric"}
	add = addGateway(&gw)
	if add == false {
		t.Error()
		return
	}
	var tenant = Tenant_v1{
		ID:      "nextensio",
		Name:    "foobar",
		Domains: []string{"kismis.org"},
	}
	add = addTenant(&tenant)
	if add == false {
		// The above add should have succeeded
		t.Error()
		return
	}

	tenants := db.DBFindAllTenants()
	if tenants == nil {
		t.Error()
		return
	}
	var tcluster1 = TenantCluster_v1{
		Id:      tenants[0].ID + ":sjc",
		Gateway: "sjc.nextensio.net",
		Apods:   1,
		Cpods:   1,
	}
	var tcluster2 = TenantCluster_v1{
		Id:      tenants[0].ID + ":ric",
		Gateway: "ric.nextensio.net",
		Apods:   1,
		Cpods:   1,
	}

	add = addTenantCluster_v1(tenants[0].ID, &tcluster1)
	if add == false {
		// The above add should have succeeded since sjc was added
		t.Error()
		return
	}

	add = addTenantCluster_v1(tenants[0].ID, &tcluster2)
	if add == false {
		// The above add should have succeeded since ric was added
		t.Error()
		return
	}
}

func TestOnboard_v1(t *testing.T) {
	db.DBReinit()

	addGatewayAndTenant(t)
	UserAdd_v1(t, false, "abcd", []string{})
	CertAdd_v1(t, "CACert")

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/global/get/onboard/", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
	Name      string   `json:"name" bson:"name"`
	Email     string   `json:"email" bson:"email"`
	Gateway   string   `json:"gateway" bson:"gateway"`
	Pod       int      `json:"pod" bson:"pod"`
	Connectid string   `json:"connectid" bson:"connectid"`
	Services  []string `json:"services" bson:"services"`
}

// Create tenant if first user being added. When tenant is created, two clusters
// called sjc and ric with two pods each are also created and tenant is assigned
// to both clusters. User is added to connect to pod1 in sjc.
func UserAdd_v1(t *testing.T, tenantadd bool, userid string, services []string) {
	if tenantadd {
		AddTenant_v1(t)
	}
	dbTenants := db.DBFindAllTenants()

	user := User_v1{
		Uid:       userid,
		Name:      "Gopa Kumar",
		Email:     "gopa@nextensio.net",
		Gateway:   "sjc.nextensio.net",
		Pod:       1,
		Connectid: "unused",
		Services:  services,
	}
	body, err := json.Marshal(user)
	if err != nil {
		t.Error()
		return
	}

	req, _ := http.NewRequest("POST", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/add/user", bytes.NewBuffer(body))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
}

func TestUserAdd_v1(t *testing.T) {
	db.DBReinit()
	UserAdd_v1(t, true, "gopa", []string{})
}

func TestUserGet_v1(t *testing.T) {
	db.DBReinit()
	UserAdd_v1(t, true, "gopa", []string{})
	dbTenants := db.DBFindAllTenants()

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/get/user/gopa", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/get/allusers", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
	Majver int `bson:"majver" json:"majver"`
	Minver int `bson:"minver" json:"minver"`
}

func testUserAttrHdrAdd_v1(t *testing.T) {
	// Just to get a user collection created
	UserAdd_v1(t, true, "some-user", []string{})
	dbTenants := db.DBFindAllTenants()

	attr := UserAttrHdr_v1{
		Majver: 2,
		Minver: 1,
	}
	body, err := json.Marshal(attr)
	if err != nil {
		t.Error()
		return
	}

	req, _ := http.NewRequest("POST", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/add/userattrhdr", bytes.NewBuffer(body))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/get/userattrhdr", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

	req, _ := http.NewRequest("POST", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/add/userattr", bytes.NewBuffer(body))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/get/userattr/gopa", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/get/alluserattr", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
	// Two excluding the attribute header
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

func testAttrSetAdd_v1(t *testing.T, tenant bool, name string, total int) {
	if tenant {
		AddTenant_v1(t)
	}
	dbTenants := db.DBFindAllTenants()

	attr := db.AttrSet{
		Name:      name,
		AppliesTo: "Users",
		Type:      "string",
	}

	body, err := json.Marshal(attr)
	if err != nil {
		t.Error()
		return
	}

	req, _ := http.NewRequest("POST", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/add/attrset", bytes.NewBuffer(body))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

	dbAttr := db.DBFindAllAttrSet(dbTenants[0].ID)
	if dbAttr == nil {
		t.Error()
		return
	}
	if len(dbAttr) != total {
		t.Error()
		return
	}
	found := false
	for i := 0; i < total; i++ {
		if dbAttr[i].Name == name {
			found = true
			break
		}
	}
	if !found {
		t.Error()
		return
	}
}

func TestAttrSetAdd_v1(t *testing.T) {
	db.DBReinit()
	testAttrSetAdd_v1(t, true, "foobar", 1)
}

func TestAttrSetGet_v1(t *testing.T) {
	db.DBReinit()
	testAttrSetAdd_v1(t, true, "foobar", 1)
	dbTenants := db.DBFindAllTenants()

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/get/allattrset", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
	var dbAttr []db.AttrSet
	err = json.Unmarshal(body, &dbAttr)
	if err != nil {
		t.Error()
		return
	}
	if len(dbAttr) != 1 || dbAttr[0].Name != "foobar" {
		t.Error()
		return
	}
}

type AttrDelResult struct {
	Result string `json:"Result"`
}

func TestAttrSetDel_v1(t *testing.T) {
	db.DBReinit()
	testAttrSetAdd_v1(t, true, "foobar", 1)
	testAttrSetAdd_v1(t, false, "abcd", 2)
	dbTenants := db.DBFindAllTenants()

	attr := db.AttrSet{
		Name:      "foobar",
		AppliesTo: "Users",
		Type:      "string",
	}
	body, err := json.Marshal(attr)
	if err != nil {
		t.Error()
		return
	}

	req, _ := http.NewRequest("POST", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/del/attrset", bytes.NewBuffer(body))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
	var data AttrDelResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}
	dbAttr := db.DBFindAllAttrSet(dbTenants[0].ID)
	if dbAttr == nil {
		t.Error()
		return
	}

	if len(dbAttr) != 1 || dbAttr[0].Name != "abcd" {
		t.Error()
		return
	}
}

type UserExtAttr_v1 struct {
	Hdr1 string
	Hdr2 string
}

func testUserExtAttrAdd_v1(t *testing.T, tenantadd bool, userid string) {
	db.DBReinit()
	UserAdd_v1(t, tenantadd, userid, []string{})
	dbTenants := db.DBFindAllTenants()

	attr := UserExtAttr_v1{
		Hdr1: "foobar",
		Hdr2: "abcd",
	}
	body, err := json.Marshal(attr)
	if err != nil {
		t.Error()
		return
	}

	req, _ := http.NewRequest("POST", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/add/userextattr", bytes.NewBuffer(body))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

	dbBson := db.DBFindUserExtAttr(dbTenants[0].ID)
	if dbBson == nil {
		t.Error()
		return
	}
	dbJson, jerr := json.Marshal(&dbBson)
	if jerr != nil {
		t.Error()
		return
	}
	var dbAttr UserExtAttr_v1
	err = json.Unmarshal(dbJson, &dbAttr)
	if err != nil {
		t.Error()
		return
	}
	if dbAttr.Hdr1 != "foobar" || dbAttr.Hdr2 != "abcd" {
		t.Error()
		return
	}
}

func TestUserExtAttrAdd_v1(t *testing.T) {
	db.DBReinit()
	testUserExtAttrAdd_v1(t, true, "gopa")
}

func TestUserExtAttrGet_v1(t *testing.T) {
	db.DBReinit()
	testUserExtAttrAdd_v1(t, true, "gopa")
	dbTenants := db.DBFindAllTenants()

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/get/userextattr", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
	var data router.GetUserExtAttrResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}
	dbJson, jerr := json.Marshal(&data.UEAttr)
	if jerr != nil {
		t.Error()
		return
	}
	var dbAttr UserExtAttr_v1
	err = json.Unmarshal(dbJson, &dbAttr)
	if err != nil {
		t.Error()
		return
	}
	if dbAttr.Hdr1 != "foobar" || dbAttr.Hdr2 != "abcd" {
		t.Error()
		return
	}
}

func TestUserExtAttrDel_v1(t *testing.T) {
	db.DBReinit()
	testUserExtAttrAdd_v1(t, true, "gopa")
	dbTenants := db.DBFindAllTenants()

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/del/userextattr", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
	var data router.GetUserExtAttrResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}
	dbBson := db.DBFindUserExtAttr(dbTenants[0].ID)
	if dbBson != nil {
		t.Error()
		return
	}
}

type HostAttrs_v1 struct {
	Tag      string `bson:"tag" json:"tag"`
	Location string `bson:"location" json:"location"`
}

type HostAttr_v1 struct {
	Host       string         `bson:"host" json:"host"`
	Routeattrs []HostAttrs_v1 `bson:"routeattrs" json:"routeattrs"`
}

func testHostAttrAdd_v1(t *testing.T, tenantadd bool, host string) {
	testAttrSetAdd_v1(t, tenantadd, "location", 1)
	dbTenants := db.DBFindAllTenants()

	attr := HostAttr_v1{
		Host:       host,
		Routeattrs: []HostAttrs_v1{{Tag: "v1", Location: "boston"}},
	}
	body, err := json.Marshal(attr)
	if err != nil {
		t.Error()
		return
	}

	req, _ := http.NewRequest("POST", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/add/hostattr", bytes.NewBuffer(body))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

	dbBson := db.DBFindHostAttr(dbTenants[0].ID, "google.com")
	if dbBson == nil {
		t.Error()
		return
	}
	dbJson, jerr := json.Marshal(&dbBson)
	if jerr != nil {
		t.Error()
		return
	}
	var dbAttr HostAttr_v1
	err = json.Unmarshal(dbJson, &dbAttr)
	if err != nil {
		t.Error()
		return
	}
	if dbAttr.Host != "google.com" || len(dbAttr.Routeattrs) != 1 {
		t.Error()
		return
	}
}

func TestHostAttrAdd_v1(t *testing.T) {
	db.DBReinit()
	testHostAttrAdd_v1(t, true, "google.com")
}

func TestHostAttrGet_v1(t *testing.T) {
	db.DBReinit()
	testHostAttrAdd_v1(t, true, "google.com")
	dbTenants := db.DBFindAllTenants()

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/get/hostattr/google.com", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
	var data router.GethostResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}

	dbJson, jerr := json.Marshal(&data.HAttr)
	if jerr != nil {
		t.Error()
		return
	}
	var dbAttr HostAttr_v1
	err = json.Unmarshal(dbJson, &dbAttr)
	if err != nil {
		t.Error()
		return
	}
	if dbAttr.Host != "google.com" || len(dbAttr.Routeattrs) != 1 {
		t.Error()
		return
	}
}

func TestHostAttrDel_v1(t *testing.T) {
	db.DBReinit()
	testHostAttrAdd_v1(t, true, "google.com")
	dbTenants := db.DBFindAllTenants()

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/del/hostattr/google.com", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
	var data router.GetUserExtAttrResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}
	dbBson := db.DBFindHostAttr(dbTenants[0].ID, "google.com")
	if dbBson != nil {
		t.Error()
		return
	}
}

func TestHostAttrGetAll_v1(t *testing.T) {
	db.DBReinit()
	testHostAttrAdd_v1(t, true, "google.com")
	testHostAttrAdd_v1(t, false, "yahoo.com")
	dbTenants := db.DBFindAllTenants()

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/get/allhostattr", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
	var data []HostAttr_v1
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
		if data[i].Host == "google.com" {
			found++
		}
		if data[i].Host == "yahoo.com" {
			found++
		}
	}
	if found != 2 {
		t.Error()
		return
	}
}

type HostAttrHdr_v1 struct {
	Majver int `bson:"majver" json:"majver"`
	Minver int `bson:"minver" json:"minver"`
}

func testHostAttrHdrAdd_v1(t *testing.T) {
	testHostAttrAdd_v1(t, true, "google.com")
	dbTenants := db.DBFindAllTenants()
	attr := BundleAttrHdr_v1{
		Majver: 2,
		Minver: 1,
	}
	body, err := json.Marshal(attr)
	if err != nil {
		t.Error()
		return
	}

	req, _ := http.NewRequest("POST", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/add/hostattrhdr", bytes.NewBuffer(body))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

	dbHdr := db.DBFindHostAttrHdr(dbTenants[0].ID)
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
func TestHostttrHdrAdd_v1(t *testing.T) {
	db.DBReinit()
	testHostAttrHdrAdd_v1(t)
}

func TestHostAttrHdrGet_v1(t *testing.T) {
	db.DBReinit()
	testHostAttrHdrAdd_v1(t)
	dbTenants := db.DBFindAllTenants()

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/get/hostattrhdr", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

func testUserDel(t *testing.T, user string) {
	dbTenants := db.DBFindAllTenants()

	udoc := db.DBFindUser(dbTenants[0].ID, user)
	if udoc == nil {
		t.Error()
		return
	}
	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/del/user/"+user, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
	if db.DBFindUser(dbTenants[0].ID, user) != nil ||
		db.DBFindUserAttr(dbTenants[0].ID, user) != nil {
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
	Bundlename string   `json:"name" bson:"name"`
	Gateway    string   `json:"gateway" bson:"gateway"`
	Pod        string   `json:"pod" bson:"pod"`
	Connectid  string   `json:"connectid" bson:"connectid"`
	Services   []string `json:"services" bson:"services"`
}

// Create tenant if first bundle being added. When tenant is created, two clusters
// called sjc and ric with two pods each are also created and tenant is assigned
// to both clusters. Bundle is added to connect to pod1 in sjc.
func testBundleAdd_v1(t *testing.T, tenantadd bool, bid string, services []string) {
	if tenantadd {
		AddTenant_v1(t)
	}
	dbTenants := db.DBFindAllTenants()

	user := Bundle_v1{
		Bid:        bid,
		Bundlename: "Google Youtube service",
		Gateway:    "sjc.nextensio.net",
		Pod:        bid,
		Connectid:  "unused",
		Services:   services,
	}
	body, err := json.Marshal(user)
	if err != nil {
		t.Error()
		return
	}

	req, _ := http.NewRequest("POST", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/add/bundle", bytes.NewBuffer(body))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
		t.Log(data.Result)
		t.Error()
		return
	}

	dbBundle := db.DBFindBundle(dbTenants[0].ID, user.Bid)
	if dbBundle == nil {
		t.Error()
		return
	}
	clUser := db.DBFindClusterBundle(db.DBGetClusterName(user.Gateway), dbTenants[0].ID+":"+user.Bid)
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

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/get/bundle/youtube", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/get/allbundles", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
	Majver int `bson:"majver" json:"majver"`
	Minver int `bson:"minver" json:"minver"`
}

func testBundleAttrHdrAdd_v1(t *testing.T) {
	// Just to get a bundle collection created
	testBundleAdd_v1(t, true, "some-bundle", []string{})
	dbTenants := db.DBFindAllTenants()
	attr := BundleAttrHdr_v1{
		Majver: 2,
		Minver: 1,
	}
	body, err := json.Marshal(attr)
	if err != nil {
		t.Error()
		return
	}

	req, _ := http.NewRequest("POST", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/add/bundleattrhdr", bytes.NewBuffer(body))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/get/bundleattrhdr", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

	req, _ := http.NewRequest("POST", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/add/bundleattr", bytes.NewBuffer(body))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/get/bundleattr/youtube", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/get/allbundleattr", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
	// Two without the attribute header
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

func testBundleDel(t *testing.T, bundle string) {
	dbTenants := db.DBFindAllTenants()

	udoc := db.DBFindBundle(dbTenants[0].ID, bundle)
	if udoc == nil {
		t.Error()
		return
	}
	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID+"/del/bundle/"+bundle, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
	if db.DBFindBundle(dbTenants[0].ID, bundle) != nil ||
		db.DBFindBundleAttr(dbTenants[0].ID, bundle) != nil ||
		db.DBFindClusterBundle(db.DBGetClusterName(udoc.Gateway), dbTenants[0].ID+":"+bundle) != nil {
		t.Error()
		return
	}
}

func TestBundleDel(t *testing.T) {
	db.DBReinit()
	testBundleAttrAdd_v1(t, true, "youtube")
	testBundleDel(t, "youtube")
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

	req, _ := http.NewRequest("POST", "http://127.0.0.1:8080/api/v1/global/add/cert", bytes.NewBuffer(body))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/global/get/cert/"+"rootCA", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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

	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/global/get/allcerts", nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/api/v1/global/del/cert/"+name, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+AccessToken)
	resp, err := client.Do(req)
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
