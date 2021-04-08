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

type Route_v1 struct {
	Route string `json:"route" bson:"_id"`
	Tag   string `json:"tag" bson:"tag"`
}

func RouteAdd_v1(t *testing.T, addtenant bool, routeid string) {
	if addtenant {
		AddTenant_v1(t)
		UserAdd_v1(t, false, "gopa", []string{})
	}
	dbTenants := db.DBFindAllTenants()

	route := Route_v1{
		Route: routeid,
		Tag:   "version1",
	}
	body, err := json.Marshal(route)
	if err != nil {
		t.Error()
		return
	}
	resp, err := http.Post("http://127.0.0.1:8080/api/v1/tenant/"+dbTenants[0].ID.Hex()+"/add/route", "application/json", bytes.NewBuffer(body))
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
	var data router.AddrouteResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}

	dbTenant := db.DBFindRoute(dbTenants[0].ID, route.Route)
	if dbTenant == nil {
		t.Error()
		return
	}
}

func TestRouteAdd_v1(t *testing.T) {
	db.DBReinit()
	RouteAdd_v1(t, true, "gopa:www.google.com")
}

func TestRouteGet_v1(t *testing.T) {
	db.DBReinit()
	RouteAdd_v1(t, true, "gopa:www.google.com")
	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/tenant/" + dbTenants[0].ID.Hex() + "/get/route/gopa:www.google.com")
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
	var data router.GetrouteResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}
	if string(data.Tag) != "version1" {
		t.Error()
		return
	}
}

func TestGetAllRoutes_v1(t *testing.T) {
	db.DBReinit()

	RouteAdd_v1(t, true, "gopa:www.google.com")
	RouteAdd_v1(t, false, "gopa:www.yahoo.com")

	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/tenant/" + dbTenants[0].ID.Hex() + "/get/allroutes")
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
	var data []db.Route
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
		if data[i].Route == "gopa:www.google.com" {
			found++
		}
		if data[i].Route == "gopa:www.yahoo.com" {
			found++
		}
	}
	if found != 2 {
		t.Error()
		return
	}
}

func RouteDel_v1(t *testing.T, name string) {
	dbTenants := db.DBFindAllTenants()

	resp, err := http.Get("http://127.0.0.1:8080/api/v1/tenant/" + dbTenants[0].ID.Hex() + "/del/route/" + name)
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
	var data router.DelrouteResult
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Error()
		return
	}
	if data.Result != "ok" {
		t.Error()
		return
	}
	if db.DBFindAllRoutes(dbTenants[0].ID) != nil {
		t.Error()
		return
	}
}

func TestRouteDel_v1(t *testing.T) {
	db.DBReinit()
	RouteAdd_v1(t, true, "gopa:www.google.com")
	RouteDel_v1(t, "gopa:www.google.com")
}
