package router

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"nextensio/controller/db"
	"nextensio/controller/utils"
	"time"

	"github.com/golang/glog"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func rdonlyOnboard() {
	// This route is used by the agent while onboarding, agent presents access-token, device-id and
	// tenant-id and expects to get information like the gateway in response
	addRoute("/api/v1/onboard/{access-token}", "GET", onboardHandler)

	// This route is used to get all gateways
	addRoute("/api/v1/getallgateways", "GET", getAllGatewaysHandler)

	// This route is used to get all tenants
	addRoute("/api/v1/getalltenants", "GET", getAllTenantsHandler)

	// This route is used to get all users
	addRoute("/api/v1/getallusers/{tenant-uuid}", "GET", getAllUsersHandler)

	// This route is used to get bundle attribute headers
	addRoute("/api/v1/getbundleattrhdr/{tenant-uuid}", "GET", getBundleAttrHdrHandler)

	// This route is used to get user attribute headers
	addRoute("/api/v1/getuserattrhdr/{tenant-uuid}", "GET", getUserAttrHdrHandler)

	// This route is used to get all user attributes
	addRoute("/api/v1/getalluserattr/{tenant-uuid}", "GET", getAllUserAttrHandler)

	// This route is used to get all bundles
	addRoute("/api/v1/getallbundles/{tenant-uuid}", "GET", getAllBundlesHandler)

	// This route is used to get all bundle attributes
	addRoute("/api/v1/getallbundleattr/{tenant-uuid}", "GET", getAllBundleAttrHandler)

	// This route is used to get basic user info
	addRoute("/api/v1/getuser/{tenant-uuid}/{userid}", "GET", getuserHandler)

	// This route is used to get user attributes that decide the policies applied to the user etc.
	addRoute("/api/v1/getuserattr/{tenant-uuid}/{userid}", "GET", getuserAttrHandler)

	// This route is used to get basic application info
	addRoute("/api/v1/getbundle/{tenant-uuid}/{bid}", "GET", getbundleHandler)

	// This route is used to get application attributes that are used with OPA.
	addRoute("/api/v1/getbundleattr/{tenant-uuid}/{bid}", "GET", getbundleAttrHandler)
}

func rdwrOnboard() {
	// This route is used to add new gateways, gateways can be multi-tenant
	addRoute("/api/v1/addgateway", "POST", addgatewayHandler)

	// This route is used by the controller admin to addd a new tenant
	addRoute("/api/v1/addtenant", "POST", addtenantHandler)

	// This route is used to delete tenants
	addRoute("/api/v1/deltenant/{tenant-uuid}", "GET", deltenantHandler)

	// This route is used to add new users with basic user info
	addRoute("/api/v1/adduser", "POST", adduserHandler)

	// This route is used to delete users
	addRoute("/api/v1/deluser/{tenant-uuid}/{userid}", "GET", deluserHandler)

	// This route is used to add new bundle attribute headers
	addRoute("/api/v1/addbundleattrhdr", "POST", addBundleAttrHdrHandler)

	// This route is used to add new user attribute headers
	addRoute("/api/v1/adduserattrhdr", "POST", addUserAttrHdrHandler)

	// This route is used to add attributes that decide the policies applied to the user etc.
	addRoute("/api/v1/adduserattr", "POST", adduserAttrHandler)

	// This route is used to add new applications with basic application info
	addRoute("/api/v1/addbundle", "POST", addbundleHandler)

	// This route is used to delete bundles
	addRoute("/api/v1/delbundle/{tenant-uuid}/{bid}", "GET", delbundleHandler)

	// This route is used to add app attributes that are used with OPA policies.
	addRoute("/api/v1/addbundleattr", "POST", addbundleAttrHandler)
}

type AddtenantResult struct {
	Result string `json:"Result"`
}

// Add a new tenant, with information like the SSO engine used by the
// customers/agents in the tenant
func addtenantHandler(w http.ResponseWriter, r *http.Request) {
	var result AddtenantResult
	var data db.Tenant

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
	err = db.DBAddTenant(&data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

// Get all tenants
func getAllTenantsHandler(w http.ResponseWriter, r *http.Request) {
	tenants := db.DBFindAllTenants()
	if tenants == nil {
		tenants = make([]db.Tenant, 0)
	}
	utils.WriteResult(w, tenants)

}

type DeltenantResult struct {
	Result string `json:"Result"`
}

// Delete a tenant
func deltenantHandler(w http.ResponseWriter, r *http.Request) {
	var result GetuserResult

	v := mux.Vars(r)
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Bad tenant id"
		utils.WriteResult(w, result)
		return
	}

	if db.DBFindAllUsers(uuid) != nil {
		result.Result = "Tenant still has users"
		utils.WriteResult(w, result)
		return
	}
	if db.DBFindAllBundles(uuid) != nil {
		result.Result = "Tenant still has bundles"
		utils.WriteResult(w, result)
		return
	}
	if db.DBFindAllPolicies(uuid) != nil {
		result.Result = "Tenant still has policies"
		utils.WriteResult(w, result)
		return
	}
	err = db.DBDelUserAttrHdr(uuid)
	if err != nil {
		result.Result = "Failed to delete user attribute header"
		utils.WriteResult(w, result)
		return
	}
	err = db.DBDelBundleAttrHdr(uuid)
	if err != nil {
		result.Result = "Failed to delete bundle attribute header"
		utils.WriteResult(w, result)
		return
	}

	err = db.DBDelTenant(uuid)
	if err != nil {
		result.Result = err.Error()
	} else {
		result = GetuserResult{Result: "ok"}
	}
	utils.WriteResult(w, result)
}

type AddgatewayResult struct {
	Result string `json:"Result"`
}

// Add a Nextensio gateway
func addgatewayHandler(w http.ResponseWriter, r *http.Request) {
	var result AddgatewayResult
	var data db.Gateway

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
	err = db.DBAddGateway(&data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

// Get all gateways
func getAllGatewaysHandler(w http.ResponseWriter, r *http.Request) {
	gws := db.DBFindAllGateways()
	if gws == nil {
		gws = make([]db.Gateway, 0)
	}
	utils.WriteResult(w, gws)

}

type onboardData struct {
	Userid string             `json:"email"`
	Tenant primitive.ObjectID `json:"tenant"`
}
type OnboardResult struct {
	Result    string `json:"Result"`
	Userid    string `json:"userid"`
	Tenant    string `json:"tenant"`
	Gateway   string `json:"gateway"`
	Connectid string `json:"connectid"`
}

// An agent wants to be onboarded, verify its access-token and return
// information that the agent wants, like the NXT gateway to use etc.
// TODO: We are assuming that all the Outh2 servers will have a "userinfo"
// end point and that all of them will return the user id in the "sub" field
// etc. This will for sure not be the case across different Oauth servers and
// will end up needing rework as we support different ones (okta, google, azure etc.)
func onboardHandler(w http.ResponseWriter, r *http.Request) {
	var result OnboardResult
	var data onboardData

	v := mux.Vars(r)
	access := v["access-token"]

	req, err := http.NewRequest("GET", IDP+"/userinfo", nil)
	if err != nil {
		result.Result = "Userinfo req failed"
		utils.WriteResult(w, result)
		return
	}
	req.Header.Add("Authorization", "Bearer "+access)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		result.Result = "Userinfo get failed"
		utils.WriteResult(w, result)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		result.Result = "Userinfo read fail"
		utils.WriteResult(w, result)
		return
	}

	// Right now we are just checking that the acess-token gave us some valid
	// user-info, we are not really "using" the user-info yet
	err = json.Unmarshal(body, &data)
	if err != nil {
		result.Result = "Error parsing json"
		utils.WriteResult(w, result)
		return
	}
	if utils.GetEnv("TEST_ENVIRONMENT", "false") == "true" {
		tenant := db.DBFindUserAnyTenant(data.Userid)
		if tenant == nil {
			result.Result = "Cannot retrieve tenant for user"
			utils.WriteResult(w, result)
			return
		}
		data.Tenant = *tenant
	}
	tenant := db.DBFindTenant(data.Tenant)
	if tenant == nil {
		result.Result = "Tenant not found"
		utils.WriteResult(w, result)
		return
	}
	user := db.DBFindUser(data.Tenant, data.Userid)
	if user.Uid != data.Userid {
		result.Result = "IDP / controller username mismatch"
		utils.WriteResult(w, result)
		return
	}
	result.Result = "ok"
	result.Userid = data.Userid
	result.Tenant = data.Tenant.Hex()
	result.Connectid = user.Connectid
	// TODO: This needs modification where we return the appropriate gateway from
	// the list to the agent, the appropriate geo-located gateway using maxmind maybe ?
	result.Gateway = tenant.Gateways[0]
	utils.WriteResult(w, result)

	glog.Info("User ", data.Userid, " tenant ", data.Tenant, " signed in")
}

type AdduserResult struct {
	Result string `json:"Result"`
}

// Add a new user, with basic information that identifies the user
func adduserHandler(w http.ResponseWriter, r *http.Request) {
	var result AdduserResult
	var data db.User

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
	err = db.DBAddUser(&data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type GetuserResult struct {
	Result string `json:"Result"`
	db.User
}

// Get a user
func getuserHandler(w http.ResponseWriter, r *http.Request) {
	var result GetuserResult

	v := mux.Vars(r)
	userid := v["userid"]
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Bad tenant id"
		utils.WriteResult(w, result)
		return
	}

	user := db.DBFindUser(uuid, userid)
	if user == nil {
		result.Result = "Cannot find user"
	} else {
		result = GetuserResult{Result: "ok", User: *user}
	}
	utils.WriteResult(w, result)
}

// Get all users
func getAllUsersHandler(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		utils.WriteResult(w, make([]db.User, 0))
		return
	}
	users := db.DBFindAllUsers(uuid)
	if users == nil {
		users = make([]db.User, 0)
	}
	utils.WriteResult(w, users)

}

type DeluserResult struct {
	Result string `json:"Result"`
}

// Delete a user
func deluserHandler(w http.ResponseWriter, r *http.Request) {
	var result GetuserResult

	v := mux.Vars(r)
	userid := v["userid"]
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Bad tenant id"
		utils.WriteResult(w, result)
		return
	}

	err = db.DBDelUserAttr(uuid, userid)
	if err != nil {
		result.Result = err.Error()
	} else {
		err = db.DBDelUser(uuid, userid)
		if err != nil {
			result.Result = err.Error()
		} else {
			result = GetuserResult{Result: "ok"}
		}
	}
	utils.WriteResult(w, result)
}

type AddUserAttrHdrResult struct {
	Result string `json:"Result"`
}

// Add a user's attribute headers
func addUserAttrHdrHandler(w http.ResponseWriter, r *http.Request) {
	var result AddUserAttrHdrResult
	var data db.DataHdr

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
	err = db.DBAddUserAttrHdr(&data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

// Get user attribute header
func getUserAttrHdrHandler(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		utils.WriteResult(w, make([]db.UserAttr, 0))
		return
	}
	hdr := db.DBFindUserAttrHdr(uuid)
	if hdr == nil {
		result := make([]db.DataHdr, 0)
		utils.WriteResult(w, result)
	} else {
		result := []db.DataHdr{*hdr}
		utils.WriteResult(w, result)
	}
}

type AdduserAttrResult struct {
	Result string `json:"Result"`
}

// Add a user's attributes, used to decide what policies are applied to the user etc.
func adduserAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result AdduserAttrResult
	var data db.UserAttr

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
	err = db.DBAddUserAttr(&data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type GetuserAttrResult struct {
	Result string `json:"Result"`
	db.UserAttr
}

// Get a user attribute structure
func getuserAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result GetuserAttrResult

	v := mux.Vars(r)
	userid := v["userid"]
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Bad tenant id"
		utils.WriteResult(w, result)
		return
	}
	attr := db.DBFindUserAttr(uuid, userid)
	if attr == nil {
		result.Result = "Cannot find user attributes"
	} else {
		result = GetuserAttrResult{Result: "ok", UserAttr: *attr}
	}
	utils.WriteResult(w, result)
}

// Get all users attributes
func getAllUserAttrHandler(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		utils.WriteResult(w, make([]db.UserAttr, 0))
		return
	}
	attrs := db.DBFindAllUserAttrs(uuid)
	if attrs == nil {
		attrs = make([]db.UserAttr, 0)
	}
	utils.WriteResult(w, attrs)

}

type AddBundleResult struct {
	Result string `json:"Result"`
}

// Add a new bundle, with basic information that identifies the bundle
func addbundleHandler(w http.ResponseWriter, r *http.Request) {
	var result AddBundleResult
	var data db.Bundle

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
	err = db.DBAddBundle(&data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type GetbundleResult struct {
	Result string `json:"Result"`
	db.Bundle
}

// Get a bundle attribute structure
func getbundleHandler(w http.ResponseWriter, r *http.Request) {
	var result GetbundleResult

	v := mux.Vars(r)
	bid := v["bid"]
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Bad tenant id"
		utils.WriteResult(w, result)
		return
	}

	bundle := db.DBFindBundle(uuid, bid)
	if bundle == nil {
		result.Result = "Cannot find user"
	} else {
		result = GetbundleResult{Result: "ok", Bundle: *bundle}
	}
	utils.WriteResult(w, result)
}

// Get all bundles
func getAllBundlesHandler(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		utils.WriteResult(w, make([]db.Bundle, 0))
		return
	}
	bundles := db.DBFindAllBundles(uuid)
	if bundles == nil {
		bundles = make([]db.Bundle, 0)
	}
	utils.WriteResult(w, bundles)

}

type DelbundleResult struct {
	Result string `json:"Result"`
}

// Delete a bundle
func delbundleHandler(w http.ResponseWriter, r *http.Request) {
	var result GetuserResult

	v := mux.Vars(r)
	userid := v["bid"]
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Bad tenant id"
		utils.WriteResult(w, result)
		return
	}

	err = db.DBDelBundleAttr(uuid, userid)
	if err != nil {
		result.Result = err.Error()
	} else {
		err = db.DBDelBundle(uuid, userid)
		if err != nil {
			result.Result = err.Error()
		} else {
			result = GetuserResult{Result: "ok"}
		}
	}
	utils.WriteResult(w, result)
}

type AddBundleAttrHdrResult struct {
	Result string `json:"Result"`
}

// Add a bundle's attribute headers
func addBundleAttrHdrHandler(w http.ResponseWriter, r *http.Request) {
	var result AddBundleAttrHdrResult
	var data db.DataHdr

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
	err = db.DBAddBundleAttrHdr(&data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

// Get bundle attribute header
func getBundleAttrHdrHandler(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		utils.WriteResult(w, make([]db.UserAttr, 0))
		return
	}
	hdr := db.DBFindBundleAttrHdr(uuid)
	if hdr == nil {
		result := make([]db.DataHdr, 0)
		utils.WriteResult(w, result)
	} else {
		result := []db.DataHdr{*hdr}
		utils.WriteResult(w, result)
	}
}

type AddbundleAttrResult struct {
	Result string `json:"Result"`
}

// Add a bundle's attribute, used to decide what policies are applied to the bundle etc.
func addbundleAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result AddbundleAttrResult
	var data db.BundleAttr

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
	err = db.DBAddBundleAttr(&data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type GetbundleAttrResult struct {
	Result string `json:"Result"`
	db.BundleAttr
}

// Get bundle attributes
func getbundleAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result GetbundleAttrResult

	v := mux.Vars(r)
	bid := v["bid"]
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Bad tenant id"
		utils.WriteResult(w, result)
		return
	}

	attr := db.DBFindBundleAttr(uuid, bid)
	if attr == nil {
		result.Result = "Cannot find user attributes"
	} else {
		result = GetbundleAttrResult{Result: "ok", BundleAttr: *attr}
	}
	utils.WriteResult(w, result)
}

// Get all bundle attributes
func getAllBundleAttrHandler(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		utils.WriteResult(w, make([]db.BundleAttr, 0))
		return
	}
	attrs := db.DBFindAllBundleAttrs(uuid)
	if attrs == nil {
		attrs = make([]db.BundleAttr, 0)
	}
	utils.WriteResult(w, attrs)

}
