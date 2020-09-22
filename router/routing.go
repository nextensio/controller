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

func rdonlyRoute() {
	// This route is used to retrieve a route in a tenant
	addRoute("/api/v1/getroute/{tenant-uuid}/{route}", "GET", getrouteHandler)

	// This route is used to get all routes
	addRoute("/api/v1/getallroutes/{tenant-uuid}", "GET", getAllRoutesHandler)
}

func rdwrRoute() {
	// This route is used by the controller admin to addd a new route to the tenant
	addRoute("/api/v1/addroute", "POST", addrouteHandler)

	// This route is used by the controller admin to delete a route
	addRoute("/api/v1/delroute/{tenant-uuid}/{route}", "GET", delrouteHandler)
}

type AddrouteResult struct {
	Result string `json:"Result"`
}

// Add a new Route
func addrouteHandler(w http.ResponseWriter, r *http.Request) {
	var result AddrouteResult
	var data db.Route

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
	err = db.DBAddRoute(&data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type GetrouteResult struct {
	Result string `json:"Result"`
	db.Route
}

// Get a route
func getrouteHandler(w http.ResponseWriter, r *http.Request) {
	var result GetrouteResult

	v := mux.Vars(r)
	routeid := v["route"]
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Bad tenant id"
		utils.WriteResult(w, result)
		return
	}

	route := db.DBFindRoute(uuid, routeid)
	if route == nil {
		result.Result = "Cannot find route"
	} else {
		result = GetrouteResult{Result: "ok", Route: *route}
	}
	utils.WriteResult(w, result)
}

// Get all routes
func getAllRoutesHandler(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		utils.WriteResult(w, make([]db.Route, 0))
		return
	}

	routes := db.DBFindAllRoutes(uuid)
	if routes == nil {
		routes = make([]db.Route, 0)
	}
	utils.WriteResult(w, routes)

}

type DelrouteResult struct {
	Result string `json:"Result"`
}

// Delete a route
func delrouteHandler(w http.ResponseWriter, r *http.Request) {
	var result DelrouteResult

	v := mux.Vars(r)
	route := v["route"]
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Bad tenant id"
		utils.WriteResult(w, result)
		return
	}

	err = db.DBDelRoute(uuid, route)
	if err != nil {
		result.Result = err.Error()
	} else {
		result = DelrouteResult{Result: "ok"}
	}
	utils.WriteResult(w, result)
}
