package router

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"nextensio/controller/db"
	"nextensio/controller/utils"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
)

func rdonlyOnboard() {
	// This route is used by the agent while onboarding, agent presents access-token, device-id and
	// tenant-id and expects to get information like the gateway in response
	getGlobalRoute("/onboard", "GET", onboardHandler)

	//*******************************************************************/
	//            In Nextensio DB
	//*******************************************************************/
	// This route is used to get all gateways
	getGlobalRoute("/allgateways", "GET", getAllGatewaysHandler)

	// This route is used to retrieve a certificate
	getGlobalRoute("/cert/{certid}", "GET", getcertHandler)

	// This route is used to get all certificates
	getGlobalRoute("/allcerts", "GET", getAllCertsHandler)

	// This route is used to get all tenants
	getGlobalRoute("/alltenants", "GET", getAllTenantsHandler)

	//*******************************************************************/
	//            In Per-tenant DB
	//*******************************************************************/
	// This route is used to get all users for a tenant
	getTenantRoute("/allusers", "GET", getAllUsersHandler)

	// This route is used to get all possible attributes for users/bundles
	getTenantRoute("/allattrset", "GET", getAllAttrSet)

	// This route is used to get bundle attributes header for a tenant
	getTenantRoute("/bundleattrhdr", "GET", getBundleAttrHdrHandler)

	// This route is used to get user attributes header for a tenant
	getTenantRoute("/userattrhdr", "GET", getUserAttrHdrHandler)

	// This route is used to get user extended attributes for a tenant
	getTenantRoute("/userextattr", "GET", getUserExtAttrHandler)

	// This route is used to get all user attributes for a tenant
	getTenantRoute("/alluserattr", "GET", getAllUserAttrHandler)

	// This route is used to get all bundles for a tenant
	getTenantRoute("/allbundles", "GET", getAllBundlesHandler)

	// This route is used to get all bundle attributes for a tenant
	getTenantRoute("/allbundleattr", "GET", getAllBundleAttrHandler)

	// This route is used to get host attributes header for a tenant
	getTenantRoute("/hostattrhdr", "GET", getHostAttrHdrHandler)

	// This route is used to get all host attributes for a tenant
	getTenantRoute("/allhostattr", "GET", getAllHostAttrHandler)

	// This route is used to get attributes for a specific host
	getTenantRoute("/hostattr/{host}", "GET", getHostAttrHandler)

	// This route is used to get basic info for a specific user
	getTenantRoute("/user/{userid}", "GET", getUserHandler)

	// This route is used to get attributes for a specific user
	getTenantRoute("/userattr/{userid}", "GET", getUserAttrHandler)

	// This route is used to get basic info for a specific app-bundle
	getTenantRoute("/bundle/{bid}", "GET", getBundleHandler)

	// This route is used to get application attributes for a specific app-bundle
	getTenantRoute("/bundleattr/{bid}", "GET", getBundleAttrHandler)

	// This route is used to get all cluster assignments for a tenant
	getTenantRoute("/alltenantclusters", "GET", getAllClustersForTenantHandler)

	// This route is used to get a specific cluster assignment for a tenant
	getTenantRoute("/tenantcluster/{gateway}", "GET", getTenantClusterHandler)

	// This route is used to get a specific user onboard log entry
	getTenantRoute("/onboardlog/{userid}", "GET", getOnboardLogHandler)

	// This route is used to get a specific user onboard log entry
	getTenantRoute("/allgateways", "GET", getAllTenantGatewaysHandler)
}

func rdwrOnboard() {
	//*******************************************************************/
	//            In Nextensio DB
	//*******************************************************************/
	// This route is used to add new gateways, gateways can be multi-tenant
	addGlobalRoute("/gateway", "POST", addgatewayHandler)

	// This route deletes a gateway that is not in use by any tenant
	delGlobalRoute("/gateway/{name}", "GET", delgatewayHandler)

	// This route is used to add new certificates
	addGlobalRoute("/cert", "POST", addcertHandler)

	// This route deletes a gateway that is not in use by any tenant
	delGlobalRoute("/cert/{certid}", "GET", delcertHandler)

	// This route is used by the controller admin to addd a new tenant
	addGlobalRoute("/tenant", "POST", addtenantHandler)

	// This route is used to delete tenants
	delGlobalRoute("/tenant/{tenant-uuid}", "GET", deltenantHandler)

	noauthRoute("/signup", "POST", signupHandler)

	//*******************************************************************/
	//            In Per-tenant DB
	//*******************************************************************/
	// This route is used to add new users with basic user info
	addTenantRoute("/user", "POST", addUserHandler)

	// This route is used to delete users. Both user info and user attribute
	// docs will be deleted for specified user
	delTenantRoute("/user/{userid}", "GET", delUserHandler)

	// This route is used to add all possible attributes for users/bundles
	addTenantRoute("/attrset", "POST", addAttrSet)

	// This route is used to delete a set of attributes for users/bundles
	delTenantRoute("/attrset", "POST", delAttrSet)

	// This route is used to add new user attributes header
	addTenantRoute("/userattrhdr", "POST", addUserAttrHdrHandler)

	// This route is used to add new user extended attributes
	addTenantRoute("/userextattr", "POST", addUserExtAttrHandler)

	// This route is used to add bundle attributes header
	addTenantRoute("/bundleattrhdr", "POST", addBundleAttrHdrHandler)

	// This route is used to add host attributes header
	addTenantRoute("/hostattrhdr", "POST", addHostAttrHdrHandler)

	// This route is used to add attributes for a user
	addTenantRoute("/userattr", "POST", addUserAttrHandler)

	// This route is used to add attributes for an app-bundle
	addTenantRoute("/bundleattr", "POST", addBundleAttrHandler)

	// This route is used to add host attributes for a tenant
	addTenantRoute("/hostattr", "POST", addHostAttrHandler)

	// This route is used to add a new app-bundle with basic info
	addTenantRoute("/bundle", "POST", addBundleHandler)

	// This route is used to delete a specific app-bundle
	// Both app-bundle info and app-bundle attribute docs will be deleted
	delTenantRoute("/bundle/{bid}", "GET", delBundleHandler)

	// This route is used to delete user extended attributes
	delTenantRoute("/userextattr", "GET", delUserExtAttrHandler)

	// This route is used to get attributes for a specific host
	delTenantRoute("/hostattr/{host}", "GET", delHostAttrHandler)

	// This route is used to add or update a cluster assignment for a tenant
	addTenantRoute("/tenantcluster", "POST", addTenantClusterHandler)

	// This route is used to delete a cluster assignment for a tenant
	delTenantRoute("/tenantcluster/{gateway}", "GET", delTenantClusterHandler)

	// This route is used to delete an onboarding log entry for a user
	delTenantRoute("/onboardlog/{userid}", "GET", delOnboardLogHandler)
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult
	var signup db.Signup

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = json.Unmarshal(body, &signup)
	if err != nil {
		result.Result = "Error parsing json"
		utils.WriteResult(w, result)
		return
	}

	id, tenant, _, err := IdpGetUser(API, TOKEN, signup.Email)
	if err == nil && id != "" {
		if tenant == signup.Tenant {
			result.Result = "You have already signed up, please check your email, activate the account and login here with your password"
			utils.WriteResult(w, result)
			return
		} else {
			result.Result = "Userid is already assigned to tenant " + tenant + ". To reassign userid to new tenant, login to the old tenant, delete the userid under Users and signup again for the new tenant"
			utils.WriteResult(w, result)
			return
		}
	}
	if db.DBFindTenant(signup.Tenant) != nil {
		result.Result = "Enterprise ID already taken, please signup for another enterprise, or contact admin for the enterprise to get you an account in this enterprise"
		utils.WriteResult(w, result)
		return
	}

	_, err = IdpAddUser(API, TOKEN, signup.Email, signup.Tenant, "admin")
	if err != nil {
		result.Result = "Failure adding user, please try again: " + err.Error()
		utils.WriteResult(w, result)
		return
	}

	var data db.Tenant
	data.ID = signup.Tenant
	err = db.DBAddTenant(&data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	err, gws := db.DBFindAllGateways()
	if err != nil {
		result.Result = "Failure fetching gateways, please try again: " + err.Error()
		utils.WriteResult(w, result)
		return
	}
	for _, g := range gws {
		tcl := db.TenantCluster{Gateway: g.Name, Image: "", ApodSets: 1, ApodRepl: 1}
		err = db.DBAddTenantCluster(data.ID, &tcl)
		if err != nil {
			result.Result = err.Error()
			utils.WriteResult(w, result)
			return
		}
	}

	var user db.User
	user.Uid = signup.Email
	user.Email = signup.Email
	err = db.DBAddUser(signup.Tenant, &user)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}
	// Add "base" attributes
	err = db.DBAddUserAttr(signup.Tenant, user.Uid, nil)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	accessPolicy := "package app.access\n\nallow = true\n"
	routePolicy := "package user.routing\n\ndefault route_tag = \"\"\n"
	policy := db.Policy{PolicyId: "AccessPolicy", Rego: []rune(accessPolicy)}
	err = db.DBAddPolicy(signup.Tenant, &policy)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}
	policy = db.Policy{PolicyId: "RoutePolicy", Rego: []rune(routePolicy)}
	err = db.DBAddPolicy(signup.Tenant, &policy)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
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
	uuid := v["tenant-uuid"]

	if db.DBFindAllUsers(uuid) != nil {
		result.Result = "Tenant still has users"
		utils.WriteResult(w, result)
		return
	}
	if db.DBFindAllUserAttrs(uuid) != nil {
		result.Result = "Tenant still has user attribute docs"
		utils.WriteResult(w, result)
		return
	}
	if db.DBFindAllBundles(uuid) != nil {
		result.Result = "Tenant still has bundles"
		utils.WriteResult(w, result)
		return
	}
	if db.DBFindAllBundleAttrs(uuid) != nil {
		result.Result = "Tenant still has bundle attribute docs"
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
	err, cls := db.DBFindAllClustersForTenant(uuid)
	if err != nil {
		result.Result = "Error fetching gateways: " + err.Error()
		utils.WriteResult(w, result)
		return
	}
	for _, cl := range cls {
		err := db.DBDelTenantCluster(uuid, cl.Name)
		if err != nil {
			result.Result = err.Error()
			utils.WriteResult(w, result)
			return
		}
	}
	// DBDelTenant() will remove all header docs for tenant collections
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
	var inuse int

	v := mux.Vars(r)
	name := v["name"]

	inuse = db.DBGatewayInUse(name)
	if inuse {
		result.Result = "Gateway not found"
		utils.WriteResult(w, result)
		return
	}

	if inuse > 0 {
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
	_, gws := db.DBFindAllGateways()
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
	Userid string `json:"email"`
	Tenant string `json:"tenant"`
}
type OnboardResult struct {
	Result    string   `json:"Result"`
	Userid    string   `json:"userid"`
	Tenant    string   `json:"tenant"`
	Gateway   string   `json:"gateway"`
	Domains   []string `json:"domains"`
	Connectid string   `json:"connectid"`
	Cluster   string   `json:"cluster"`
	Podname   string   `json:"podname"`
	Cacert    []rune   `json:"cacert"`
	Services  []string `json:"services"`
}

func onboardHandler(w http.ResponseWriter, r *http.Request) {
	var result OnboardResult
	var data onboardData

	data.Userid = r.Context().Value("userid").(string)
	data.Tenant = r.Context().Value("user-tenant").(string)

	tenant := db.DBFindTenant(data.Tenant)
	if tenant == nil {
		result.Result = "Tenant not found"
		utils.WriteResult(w, result)
		return
	}
	user := db.DBFindUser(data.Tenant, data.Userid)
	if user != nil {
		result.Connectid = user.Connectid
		result.Services = user.Services
		result.Gateway = user.Gateway
		result.Cluster = db.DBGetClusterName(user.Gateway)
	} else {
		bundle := db.DBFindBundle(data.Tenant, data.Userid)
		if bundle != nil {
			result.Connectid = bundle.Connectid
			if bundle.Pod != "" {
				result.Connectid = bundle.Pod
			}
			result.Services = bundle.Services
			result.Gateway = bundle.Gateway
			result.Cluster = db.DBGetClusterName(bundle.Gateway)
		} else {
			result.Result = "IDP user/bundle not found on controller"
			utils.WriteResult(w, result)
			return
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
	result.Tenant = data.Tenant
	result.Cacert = cert.Cert
	result.Domains = tenant.Domains
	utils.WriteResult(w, result)

	var onbl db.OnboardLog
	onbl.Uid = result.Userid
	onbl.Gw = result.Gateway
	onbl.Connectid = result.Connectid
	tbytes, _ := time.Now().MarshalJSON()
	onbl.OnbTime = string(tbytes)
	err := db.DBAddOnboardLog(result.Tenant, &onbl)
	if err != nil {
		glog.Errorf("Onboarding log add error %v (for %v)", err, onbl)
	}
	glog.Infof("User %s of tenant %s with connectid %s signed in. Gateway %s assigned",
		data.Userid, data.Tenant, result.Connectid, result.Gateway)
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
	uuid := r.Context().Value("tenant").(string)
	_, err = IdpAddUser(API, TOKEN, data.Uid, uuid, "regular")
	if err != nil {
		msg := "Adding user to IDP fail:" + err.Error()
		glog.Errorf(msg)
		result.Result = msg
		utils.WriteResult(w, result)
		return
	}

	err = db.DBAddUser(uuid, &data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}
	// Add/Update base attributes
	err = db.DBAddUserAttr(uuid, data.Uid, nil)
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
	uuid := r.Context().Value("tenant").(string)
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
	uuid := r.Context().Value("tenant").(string)
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
	uuid := r.Context().Value("tenant").(string)

	err := IdpDelUser(API, TOKEN, userid, uuid)
	if err != nil {
		result.Result = "Deleting user from IDP fail: " + err.Error()
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

// Add a tenants attribute set
func addAttrSet(w http.ResponseWriter, r *http.Request) {
	var result OpResult
	var data db.AttrSet

	uuid := r.Context().Value("tenant").(string)
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Add tenant attribute set - HTTP Req Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		result.Result = "Add tenant attribute set - Error parsing json"
		utils.WriteResult(w, result)
		return
	}
	err = db.DBAddAttrSet(uuid, data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

// Del a tenants attribute set provided in the api call
func delAttrSet(w http.ResponseWriter, r *http.Request) {
	var result OpResult
	var data db.AttrSet

	uuid := r.Context().Value("tenant").(string)
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Add tenant attribute set - HTTP Req Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		result.Result = "Add tenant attribute set - Error parsing json"
		utils.WriteResult(w, result)
		return
	}
	err = db.DBDelAttrSet(uuid, data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
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
	uuid := r.Context().Value("tenant").(string)
	err = db.DBAddUserAttrHdr(uuid, &data)
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

	uuid := r.Context().Value("tenant").(string)
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

	var Uattr bson.M
	var user string
	err = json.Unmarshal(body, &Uattr)
	if err != nil {
		result.Result = "User json decode fail"
		utils.WriteResult(w, result)
		return
	}
	if v, found := Uattr["uid"]; found {
		user = fmt.Sprintf("%s", v)
		delete(Uattr, "uid")
	} else {
		result.Result = "Missing user id"
		utils.WriteResult(w, result)
		return
	}
	uuid := r.Context().Value("tenant").(string)
	err = db.DBAddUserAttr(uuid, user, Uattr)
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
	uuid := r.Context().Value("tenant").(string)
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
	uuid := r.Context().Value("tenant").(string)
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
	uuid := r.Context().Value("tenant").(string)
	_, err = IdpAddUser(API, TOKEN, data.Bid, uuid, "regular")
	if err != nil {
		msg := "Adding appGroup to IDP fail:" + err.Error()
		glog.Errorf(msg)
		result.Result = msg
		utils.WriteResult(w, result)
		return
	}

	err = db.DBAddBundle(uuid, &data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}
	// Add/update "base" attributes
	err = db.DBAddBundleAttr(uuid, data.Bid, nil)
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
	uuid := r.Context().Value("tenant").(string)
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
	uuid := r.Context().Value("tenant").(string)
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
	uuid := r.Context().Value("tenant").(string)
	err := IdpDelUser(API, TOKEN, bid, uuid)
	if err != nil {
		result.Result = "Deleting bundle from IDP fail: " + err.Error()
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
	uuid := r.Context().Value("tenant").(string)
	err = db.DBAddBundleAttrHdr(uuid, &data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

// Get  attribute set
func getAllAttrSet(w http.ResponseWriter, r *http.Request) {
	uuid := r.Context().Value("tenant").(string)
	set := db.DBFindAllAttrSet(uuid)
	if set == nil {
		result := make([]db.AttrSet, 0)
		utils.WriteResult(w, result)
	} else {
		result := set
		utils.WriteResult(w, result)
	}
}

// Get bundle attribute header
func getBundleAttrHdrHandler(w http.ResponseWriter, r *http.Request) {
	uuid := r.Context().Value("tenant").(string)
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

	var Battr bson.M
	var bid string
	err = json.Unmarshal(body, &Battr)
	if err != nil {
		result.Result = "Bundle json decode fail"
		utils.WriteResult(w, result)
		return
	}
	if v, found := Battr["bid"]; found {
		bid = fmt.Sprintf("%s", v)
		delete(Battr, "bid")
	} else {
		result.Result = "Missing bundle id"
		utils.WriteResult(w, result)
		return
	}
	uuid := r.Context().Value("tenant").(string)
	err = db.DBAddBundleAttr(uuid, bid, Battr)
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
	uuid := r.Context().Value("tenant").(string)
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
	uuid := r.Context().Value("tenant").(string)
	attrs := db.DBFindAllBundleAttrs(uuid)
	if attrs == nil {
		attrs = make([]bson.M, 0)
	}
	utils.WriteResult(w, attrs)

}

// Get host attributes header for a tenant
func getHostAttrHdrHandler(w http.ResponseWriter, r *http.Request) {
	uuid := r.Context().Value("tenant").(string)
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
	uuid := r.Context().Value("tenant").(string)
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
	uuid := r.Context().Value("tenant").(string)
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
	uuid := r.Context().Value("tenant").(string)
	err = db.DBAddHostAttrHdr(uuid, &data)
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
	uuid := r.Context().Value("tenant").(string)
	err = db.DBAddHostAttr(uuid, body)
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
	host := v["host"]
	// IP/Mask will be sent as IP_Mask since / will be interpreted as an http path
	host = strings.ReplaceAll(host, "_", "/")
	uuid := r.Context().Value("tenant").(string)
	err := db.DBDelHostAttr(uuid, host)
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

	uuid := r.Context().Value("tenant").(string)
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

	uuid := r.Context().Value("tenant").(string)
	err = db.DBAddUserExtAttr(uuid, body)
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

	uuid := r.Context().Value("tenant").(string)
	err := db.DBDelUserExtAttr(uuid)
	if err != nil {
		result.Result = err.Error()
	} else {
		result.Result = "ok"
	}
	utils.WriteResult(w, result)
}

//------------------------------Tenant allocation to clusters --------------------------------

// Allocate a tenant to a cluster, specifying the number of pods allocated
// for the tenant in the cluster and image to use for the pods (for now).
func addTenantClusterHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult
	var data db.TenantCluster

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Add tenant cluster - HTTP Req Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		result.Result = "Add tenant cluster - Error parsing json"
		utils.WriteResult(w, result)
		return
	}
	uuid := r.Context().Value("tenant").(string)
	err = db.DBAddTenantCluster(uuid, &data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type GetTenantClusResult struct {
	Result   string `json:"Result"`
	TenantCl db.TenantCluster
}

// Get a cluster assignment config for a tenant
func getTenantClusterHandler(w http.ResponseWriter, r *http.Request) {
	var result GetTenantClusResult

	v := mux.Vars(r)
	gateway := v["gateway"]
	Cluster := db.DBGetClusterName(gateway)
	uuid := r.Context().Value("tenant").(string)

	tenantcl := db.DBFindTenantCluster(uuid, Cluster)
	if tenantcl == nil {
		result.Result = "Cannot find tenant cluster/gateway"
	} else {
		result = GetTenantClusResult{Result: "ok", TenantCl: *tenantcl}
	}
	utils.WriteResult(w, result)
}

// Get all clusters assigned for a tenant
func getAllClustersForTenantHandler(w http.ResponseWriter, r *http.Request) {

	uuid := r.Context().Value("tenant").(string)
	tenantcls := db.DBFindAllClusterConfigsForTenant(uuid)
	if tenantcls == nil {
		tenantcls = make([]db.TenantCluster, 0)
	}
	utils.WriteResult(w, tenantcls)
}

// Delete a tenant cluster assignment
// When a tenant cluster assignment is deleted, need to ensure all pods
// in the cluster for that tenant are not in use, ie., no active users
// or connectors.
func delTenantClusterHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult

	v := mux.Vars(r)
	gateway := v["gateway"]
	Cluster := db.DBGetClusterName(gateway)
	uuid := r.Context().Value("tenant").(string)

	err := db.DBDelTenantCluster(uuid, Cluster)
	if err != nil {
		result.Result = err.Error()
	} else {
		result.Result = "ok"
	}
	utils.WriteResult(w, result)
}

//-----------------------------------------Onboard Log-------------------------------------

type GetOnboardLogResult struct {
	Result    string `json:"Result"`
	Gw        string `json:"gw"`
	Pod       int    `json:"pod"`
	Podnm     string `json:"podnm"`
	Connectid string `json:"connectid"`
	OnbTime   string `json:"onbtime"`
	Count     int    `json:"count"`
	PrevTime  string `json:"prevtime"`
}

// Get a user's onboarding log entry. Only the last onboarding log is kept for now.
func getOnboardLogHandler(w http.ResponseWriter, r *http.Request) {
	var result GetOnboardLogResult

	v := mux.Vars(r)
	tid := r.Context().Value("tenant").(string)
	uid := v["userid"]

	onblog := db.DBFindOnboardLog(tid, uid)
	if onblog == nil {
		result.Result = "Cannot find user onboarding log"
	} else {
		result = GetOnboardLogResult{Result: "ok",
			Gw:        onblog.Gw,
			Connectid: onblog.Connectid,
			OnbTime:   onblog.OnbTime,
			Count:     onblog.Count,
			PrevTime:  onblog.PrevTime}
	}
	utils.WriteResult(w, result)
}

func delOnboardLogHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult

	v := mux.Vars(r)
	tid := r.Context().Value("tenant").(string)
	uid := v["userid"]

	err := db.DBDelOnboardLog(tid, uid)
	if err != nil {
		result.Result = err.Error()
	} else {
		result.Result = "ok"
	}
	utils.WriteResult(w, result)
}

// Get all gateways assigned to a tenant. Well as of today the tenant has all the gateways
// in nextensio. This will change in future where each tenant might have a subset of the
// total gateways
func getAllTenantGatewaysHandler(w http.ResponseWriter, r *http.Request) {
	_, gws := db.DBFindAllGateways()
	if gws == nil {
		gws = make([]db.Gateway, 0)
	}
	utils.WriteResult(w, gws)
}
