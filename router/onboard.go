package router

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"nextensio/controller/db"
	"nextensio/controller/utils"
	"time"

	"github.com/golang/glog"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func rdonlyOnboard() {
	// This route is used by the agent while onboarding, agent presents access-token, device-id and
	// tenant-id and expects to get information like the gateway in response
	addRoute("/api/v1/onboard/{access-token}", "GET", onboardHandler)

	//*******************************************************************/
	//            In Nextensio DB
	//*******************************************************************/
	// This route is used to get all gateways
	addRoute("/api/v1/getallgateways", "GET", getAllGatewaysHandler)

	// This route is used to retrieve a certificate
	addRoute("/api/v1/getcert/{certid}", "GET", getcertHandler)

	// This route is used to get all certificates
	addRoute("/api/v1/getallcerts", "GET", getAllCertsHandler)

	// This route is used to get all tenants
	addRoute("/api/v1/getalltenants", "GET", getAllTenantsHandler)

	//*******************************************************************/
	//            In Per-tenant DB
	//*******************************************************************/
	// This route is used to get all users for a tenant
	addRoute("/api/v1/getallusers/{tenant-uuid}", "GET", getAllUsersHandler)

	// This route is used to get bundle attributes header for a tenant
	addRoute("/api/v1/getbundleattrhdr/{tenant-uuid}", "GET", getBundleAttrHdrHandler)

	// This route is used to get user attributes header for a tenant
	addRoute("/api/v1/getuserattrhdr/{tenant-uuid}", "GET", getUserAttrHdrHandler)

	// This route is used to get user extended attributes for a tenant
	addRoute("/api/v1/getuserextattr/{tenant-uuid}", "GET", getUserExtAttrHandler)

	// This route is used to get all user attributes for a tenant
	addRoute("/api/v1/getalluserattr/{tenant-uuid}", "GET", getAllUserAttrHandler)

	// This route is used to get all bundles for a tenant
	addRoute("/api/v1/getallbundles/{tenant-uuid}", "GET", getAllBundlesHandler)

	// This route is used to get all bundle attributes for a tenant
	addRoute("/api/v1/getallbundleattr/{tenant-uuid}", "GET", getAllBundleAttrHandler)

	// This route is used to get host attributes header for a tenant
	addRoute("/api/v1/gethostattrhdr/{tenant-uuid}", "GET", getHostAttrHdrHandler)

	// This route is used to get all host attributes for a tenant
	addRoute("/api/v1/getallhostattr/{tenant-uuid}", "GET", getAllHostAttrHandler)

	// This route is used to get basic info for a specific user
	addRoute("/api/v1/getuser/{tenant-uuid}/{userid}", "GET", getUserHandler)

	// This route is used to get attributes for a specific user
	addRoute("/api/v1/getuserattr/{tenant-uuid}/{userid}", "GET", getUserAttrHandler)

	// This route is used to get basic info for a specific app-bundle
	addRoute("/api/v1/getbundle/{tenant-uuid}/{bid}", "GET", getBundleHandler)

	// This route is used to get application attributes for a specific app-bundle
	addRoute("/api/v1/getbundleattr/{tenant-uuid}/{bid}", "GET", getBundleAttrHandler)

	// This route is used to get attributes for a specific host
	addRoute("/api/v1/gethostattr/{tenant-uuid}/{host}", "GET", getHostAttrHandler)
}

func rdwrOnboard() {
	//*******************************************************************/
	//            In Nextensio DB
	//*******************************************************************/
	// This route is used to add new gateways, gateways can be multi-tenant
	addRoute("/api/v1/addgateway", "POST", addgatewayHandler)

	// This route deletes a gateway that is not in use by any tenant
	addRoute("/api/v1/delgateway/{name}", "GET", delgatewayHandler)

	// This route is used to add new certificates
	addRoute("/api/v1/addcert", "POST", addcertHandler)

	// This route deletes a gateway that is not in use by any tenant
	addRoute("/api/v1/delcert/{certid}", "GET", delcertHandler)

	// This route is used by the controller admin to addd a new tenant
	addRoute("/api/v1/addtenant", "POST", addtenantHandler)

	// This route is used to delete tenants
	addRoute("/api/v1/deltenant/{tenant-uuid}", "GET", deltenantHandler)

	//*******************************************************************/
	//            In Per-tenant DB
	//*******************************************************************/
	// This route is used to add new users with basic user info
	addRoute("/api/v1/adduser", "POST", addUserHandler)

	// This route is used to delete users. Both user info and user attribute
	// docs will be deleted for specified user
	addRoute("/api/v1/deluser/{tenant-uuid}/{userid}", "GET", delUserHandler)

	// This route is used to add new user attributes header
	addRoute("/api/v1/adduserattrhdr", "POST", addUserAttrHdrHandler)

	// This route is used to add new user extended attributes
	addRoute("/api/v1/adduserextattr", "POST", addUserExtAttrHandler)

	// This route is used to add bundle attributes header
	addRoute("/api/v1/addbundleattrhdr", "POST", addBundleAttrHdrHandler)

	// This route is used to add host attributes header
	addRoute("/api/v1/addhostattrhdr", "POST", addHostAttrHdrHandler)

	// This route is used to add attributes for a user
	addRoute("/api/v1/adduserattr", "POST", addUserAttrHandler)

	// This route is used to add attributes for an app-bundle
	addRoute("/api/v1/addbundleattr", "POST", addBundleAttrHandler)

	// This route is used to add host attributes for a tenant
	addRoute("/api/v1/addhostattr", "POST", addHostAttrHandler)

	// This route is used to add a new app-bundle with basic info
	addRoute("/api/v1/addbundle", "POST", addBundleHandler)

	// This route is used to delete a specific app-bundle
	// Both app-bundle info and app-bundle attribute docs will be deleted
	addRoute("/api/v1/delbundle/{tenant-uuid}/{bid}", "GET", delBundleHandler)

	// This route is used to delete user extended attributes
	addRoute("/api/v1/deluserextattr/{tenant-uuid}", "GET", delUserExtAttrHandler)
}

type AddtenantResult struct {
	Result string `json:"Result"`
}

// Add a new tenant, with information like the SSO engine used by the
// customers/agents in the tenant
func addtenantHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult
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
// When a tenant is deleted, all users, app-bundles, host attributes,
// and policies (basically all tenant specific collections) also need
// to be deleted. Should we do that automatically here or require that
// they be separately deleted first before deleting the tenant ?
func deltenantHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult

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
	if db.DBFindAllHostAttrs(uuid) != nil {
		result.Result = "Tenant still has host attributes"
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
		result.Result = "ok"
	}
	utils.WriteResult(w, result)
}

type AddgatewayResult struct {
	Result string `json:"Result"`
}

// Add a Nextensio gateway
func addgatewayHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult
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

type DelgatewayResult struct {
	Result string `json:"Result"`
}

// Delete a Nextensio gateway
func delgatewayHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult

	v := mux.Vars(r)
	name := v["name"]

	if db.DBGatewayInUse(name) {
		result.Result = "Gateway still in use by tenants"
		utils.WriteResult(w, result)
		return
	}

	err := db.DBDelGateway(name)
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

type AddcertResult struct {
	Result string `json:"Result"`
}

// Add a Nextensio gateway
func addcertHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult
	var data db.Certificate

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
	err = db.DBAddCert(&data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type DelcertResult struct {
	Result string `json:"Result"`
}

// Delete a Nextensio gateway
func delcertHandler(w http.ResponseWriter, r *http.Request) {
	var result DelcertResult

	v := mux.Vars(r)
	name := v["certid"]

	err := db.DBDelCert(name)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type GetcertResult struct {
	Result string `json:"Result"`
	db.Certificate
}

// Get a certificate
func getcertHandler(w http.ResponseWriter, r *http.Request) {
	var result GetcertResult

	v := mux.Vars(r)
	certname := v["certid"]

	cert := db.DBFindCert(certname)
	if cert == nil {
		result.Result = "Cannot find certificate"
	} else {
		result = GetcertResult{Result: "ok", Certificate: *cert}
	}
	utils.WriteResult(w, result)
}

// Get all gateways
func getAllCertsHandler(w http.ResponseWriter, r *http.Request) {
	certs := db.DBFindAllCerts()
	if certs == nil {
		certs = make([]db.Certificate, 0)
	}
	utils.WriteResult(w, certs)

}

type onboardData struct {
	Userid string             `json:"email"`
	Tenant primitive.ObjectID `json:"tenant"`
}
type OnboardResult struct {
	Result    string   `json:"Result"`
	Userid    string   `json:"userid"`
	Tenant    string   `json:"tenant"`
	Gateway   string   `json:"gateway"`
	Domains   []string `json:"domains"`
	Connectid string   `json:"connectid"`
	Cacert    []rune   `json:"cacert"`
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
	// We are supposed to use the access token and peel it open and get further data
	// like the tenant the user belongs to etc.. The tenantid is basically the ObjectID
	// of the tenant in our database - how does that get into the accesstoken ? Well the
	// IDP (okta) should be configured such that each user has their tenant id configured
	// in the IDP (refer to gitlab.com/nextensio/agent/README.md to see how thats done).
	// And then the agent is onboarded with the IDP and we can get the tenantid from inside
	// that. As of today, for the test environment, we havent taken the trouble of creating
	// test-environment-specific users with proper tenant ids set etc.., so we just resort
	// to the hack of assuming there is only one tenant in the test environment / or even
	// if there are multiple tenants the userid is unique per tenant. Its a TODO to properly
	// configure the IDP with test users and their tenant ids etc.. and then remove this
	// TEST_ENVIRONMENT business
	if utils.GetEnv("TEST_ENVIRONMENT", "false") == "true" {
		tenant := db.DBFindUserAnyTenant(data.Userid)
		if tenant == nil {
			tenant = db.DBFindBundleAnyTenant(data.Userid)
			if tenant == nil {
				result.Result = fmt.Sprintf("Cannot retrieve tenant for user %s", data.Userid)
				utils.WriteResult(w, result)
				return
			}
		}
		data.Tenant = *tenant
	}
	tenant := db.DBFindTenant(data.Tenant)
	if tenant == nil {
		result.Result = "Tenant not found"
		utils.WriteResult(w, result)
		return
	}
	{
		user := db.DBFindUser(data.Tenant, data.Userid)
		if user != nil {
			if user.Uid != data.Userid {
				result.Result = "IDP / controller username mismatch"
				utils.WriteResult(w, result)
				return
			}
			result.Connectid = user.Connectid
			// This is used only in a test environment today, to force-associate
			// a user to a gateway
			if user.Gateway != "" {
				result.Gateway = user.Gateway
			}
		} else {
			bundle := db.DBFindBundle(data.Tenant, data.Userid)
			if bundle != nil {
				if bundle.Bid != data.Userid {
					result.Result = "IDP / controller bundlename mismatch"
					utils.WriteResult(w, result)
					return
				}
				result.Connectid = bundle.Connectid
				// This is used only in a test environment today, to force-associate
				// a user to a gateway
				if bundle.Gateway != "" {
					result.Gateway = bundle.Gateway
				}
			} else {
				result.Result = "IDP user/bundle not found on controller"
				utils.WriteResult(w, result)
				return
			}
		}
	}
	cert := db.DBFindCert("CACert")
	if cert == nil {
		result.Result = "Unable to find CA cert"
		utils.WriteResult(w, result)
		return
	}
	result.Result = "ok"
	result.Userid = data.Userid
	result.Tenant = data.Tenant.Hex()
	result.Cacert = cert.Cert
	// TODO: This needs modification where we return the appropriate gateway from
	// the list to the agent, the appropriate geo-located gateway using maxmind maybe ?
	if result.Gateway == "" {
		result.Gateway = tenant.Gateways[0]
	}
	result.Domains = tenant.Domains
	utils.WriteResult(w, result)

	glog.Info("User ", data.Userid, " tenant ", data.Tenant, " signed in")
}

type OpResult struct {
	Result string `json:"Result"`
}

// Add a new user, with basic information that identifies the user
func addUserHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult
	var data db.User

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Add user info - HTTP Req Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		result.Result = "Add user info - Error parsing json"
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
	User   db.User
}

// Get a user
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	var result GetuserResult

	v := mux.Vars(r)
	userid := v["userid"]
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Get user info - Bad tenant id"
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
		utils.WriteResult(w, make([]bson.M, 0))
		return
	}
	users := db.DBFindAllUsers(uuid)
	if users == nil {
		users = make([]bson.M, 0)
	}
	utils.WriteResult(w, users)

}

// Delete a user
func delUserHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult

	v := mux.Vars(r)
	userid := v["userid"]
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Delete User info - Bad tenant id"
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
			result.Result = "ok"
		}
	}
	utils.WriteResult(w, result)
}

// Add a user's attribute headers
func addUserAttrHdrHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult
	var data db.DataHdr

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Add user attribute header - HTTP Req Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		result.Result = "Add user attribute header - Error parsing json"
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
	var hdr []db.DataHdr

	v := mux.Vars(r)
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		utils.WriteResult(w, hdr)
		return
	}
	dhdr := db.DBFindUserAttrHdr(uuid)
	if dhdr == nil {
		utils.WriteResult(w, hdr)
	} else {
		utils.WriteResult(w, []db.DataHdr{*dhdr})
	}
}

// Add a user's attributes, used in policies applied to the user etc.
func addUserAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Add User attributes - HTTP Req Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = db.DBAddUserAttr(body)
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
	UAttr  bson.M
}

// Get a user attribute structure
func getUserAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result GetuserAttrResult

	v := mux.Vars(r)
	userid := v["userid"]
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Get user attributes - Bad tenant id"
		utils.WriteResult(w, result)
		return
	}
	attr := db.DBFindUserAttr(uuid, userid)
	if attr == nil {
		result.Result = "Cannot find user attributes"
	} else {
		result = GetuserAttrResult{Result: "ok", UAttr: *attr}
	}
	utils.WriteResult(w, result)
}

// Get all user attribute docs
func getAllUserAttrHandler(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		utils.WriteResult(w, make([]bson.M, 0))
		return
	}
	attrs := db.DBFindAllUserAttrs(uuid)
	if attrs == nil {
		attrs = make([]bson.M, 0)
	}
	utils.WriteResult(w, attrs)

}

// Add a new bundle, with basic information that identifies the bundle
func addBundleHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult
	var data db.Bundle

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Add App-bundle info - Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		result.Result = "Add App-bundle info - Error parsing json"
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
	Bundle db.Bundle
}

// Get a bundle info doc
func getBundleHandler(w http.ResponseWriter, r *http.Request) {
	var result GetbundleResult

	v := mux.Vars(r)
	bid := v["bid"]
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Get App-bundle info - Bad tenant id"
		utils.WriteResult(w, result)
		return
	}

	bundle := db.DBFindBundle(uuid, bid)
	if bundle == nil {
		result.Result = "Cannot find bundle"
	} else {
		result = GetbundleResult{Result: "ok", Bundle: *bundle}
	}
	utils.WriteResult(w, result)
}

// Get all bundle info docs
func getAllBundlesHandler(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		utils.WriteResult(w, make([]bson.M, 0))
		return
	}
	bundles := db.DBFindAllBundles(uuid)
	if bundles == nil {
		bundles = make([]bson.M, 0)
	}
	utils.WriteResult(w, bundles)

}

// Delete a bundle info doc
func delBundleHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult

	v := mux.Vars(r)
	bid := v["bid"]
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Delete App-bundle info - Bad tenant id"
		utils.WriteResult(w, result)
		return
	}

	err = db.DBDelBundleAttr(uuid, bid)
	if err != nil {
		result.Result = err.Error()
	} else {
		err = db.DBDelBundle(uuid, bid)
		if err != nil {
			result.Result = err.Error()
		} else {
			result.Result = "ok"
		}
	}
	utils.WriteResult(w, result)
}

// Add a bundle attributes header
func addBundleAttrHdrHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult
	var data db.DataHdr

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Add App-bundle attributes header - HTTP Req Read fail"
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
		utils.WriteResult(w, make([]db.DataHdr, 0))
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

// Add a bundle's attribute, used to decide what policies are applied to the bundle etc.
func addBundleAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Add App-bundle attributes - HTTP Req Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = db.DBAddBundleAttr(body)
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
	BAttr  bson.M
}

// Get bundle attributes
func getBundleAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result GetbundleAttrResult

	v := mux.Vars(r)
	bid := v["bid"]
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Get App-bundle attributes - Bad tenant id"
		utils.WriteResult(w, result)
		return
	}

	attr := db.DBFindBundleAttr(uuid, bid)
	if attr == nil {
		result.Result = "Cannot find bundle attributes"
	} else {
		result = GetbundleAttrResult{Result: "ok", BAttr: *attr}
	}
	utils.WriteResult(w, result)
}

// Get all bundle attributes
func getAllBundleAttrHandler(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		utils.WriteResult(w, make([]bson.M, 0))
		return
	}
	attrs := db.DBFindAllBundleAttrs(uuid)
	if attrs == nil {
		attrs = make([]bson.M, 0)
	}
	utils.WriteResult(w, attrs)

}

// Get host attributes header for a tenant
func getHostAttrHdrHandler(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		utils.WriteResult(w, make([]db.DataHdr, 0))
		return
	}
	hdr := db.DBFindHostAttrHdr(uuid)
	if hdr == nil {
		result := make([]db.DataHdr, 0)
		utils.WriteResult(w, result)
	} else {
		result := []db.DataHdr{*hdr}
		utils.WriteResult(w, result)
	}
}

// Get all host attributes for a tenant
func getAllHostAttrHandler(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		utils.WriteResult(w, make([]bson.M, 0))
		return
	}
	attrs := db.DBFindAllHostAttrs(uuid)
	if attrs == nil {
		attrs = make([]bson.M, 0)
	}
	utils.WriteResult(w, attrs)

}

type GethostResult struct {
	Result string `json:"Result"`
	HAttr  bson.M
}

// Get a host attributes doc
func getHostAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result GethostResult

	v := mux.Vars(r)
	host := v["host"]
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Get Host attributes - Bad tenant id"
		utils.WriteResult(w, result)
		return
	}

	hostattr := db.DBFindHostAttr(uuid, host)
	if hostattr == nil {
		result.Result = "Cannot find host attributes"
	} else {
		result = GethostResult{Result: "ok", HAttr: *hostattr}
	}
	utils.WriteResult(w, result)
}

// Add a host attributes header
func addHostAttrHdrHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult
	var data db.DataHdr

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Add Host attribute header - HTTP Req Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		result.Result = "Host attribute header - Error parsing json"
		utils.WriteResult(w, result)
		return
	}
	err = db.DBAddHostAttrHdr(&data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

// Add a bundle's attribute, used to decide what policies are applied to the bundle etc.
func addHostAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Add Host attributes - HTTP Req Read fail"
		utils.WriteResult(w, result)
		return
	}
	err = db.DBAddHostAttr(body)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

// Delete host attributes doc
func delHostAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult

	v := mux.Vars(r)
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Delete host attributes - Bad tenant id"
		utils.WriteResult(w, result)
		return
	}
	host := v["host"]

	err = db.DBDelHostAttr(uuid, host)
	if err != nil {
		result.Result = err.Error()
	} else {
		result.Result = "ok"
	}
	utils.WriteResult(w, result)
}

type GetUserExtAttrResult struct {
	Result string `json:"Result"`
	UEAttr bson.M
}

// Get user extended attributes for a tenant
func getUserExtAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result GetUserExtAttrResult

	v := mux.Vars(r)
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Get user extended attributes - Bad tenant id"
		utils.WriteResult(w, result)
		return
	}
	attr := db.DBFindUserExtAttr(uuid)
	if attr == nil {
		result.Result = "Cannot find user extended attributes"
		utils.WriteResult(w, result)
	} else {
		result = GetUserExtAttrResult{Result: "ok", UEAttr: *attr}
	}
	utils.WriteResult(w, result)
}

// Add a user extended attribute doc
func addUserExtAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Add user extended attribute - HTTP Req Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = db.DBAddUserExtAttr(body)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

// Delete user extended attributes
func delUserExtAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult

	v := mux.Vars(r)
	uuid, err := db.StrToObjectid(v["tenant-uuid"])
	if err != nil {
		result.Result = "Delete user extended attribute - Bad tenant id"
		utils.WriteResult(w, result)
		return
	}

	err = db.DBDelUserExtAttr(uuid)
	if err != nil {
		result.Result = err.Error()
	} else {
		result.Result = "ok"
	}
	utils.WriteResult(w, result)
}
