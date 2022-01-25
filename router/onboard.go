package router

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"nextensio/controller/db"
	"nextensio/controller/okta"
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

	// TODO: DEPRECATE the GET /keepalive, we need only the POST /keepaliverequest
	getGlobalRoute("/keepalive/{version}/{uuid}", "GET", keepaliveHandler)

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

	// This route is used by the tenant admin to get the tenant parameters
	getTenantRoute("/tenant", "GET", gettenantHandler)

	// This route is used to get all admin groups for a tenant
	getTenantRoute("/alladmgroups", "GET", getAllAdminGroupsHandler)

	// This route is used to get all admins for a group for a tenant
	getTenantRoute("/groupadms/{group}", "GET", getAdminsForGroupHandler)

	// This route is used to get the group admin role (usertype) of a user
	getTenantRoute("/user/adminrole/{userid}", "GET", getUserAdminRole)

	// This route is used to get all users for a tenant
	getTenantRoute("/allusers", "GET", getAllUsersHandler)

	// This route is used to get all possible attributes for users/bundles/hosts
	getTenantRoute("/allattrset", "GET", getAllAttrSet)

	// This route is used to get attributes for a specific type - users or bundles or hosts
	getTenantRoute("/attrset/{type}", "GET", getSpecificAttrSet)

	// This route is used to get bundle attributes header for a tenant
	getTenantRoute("/bundleattrhdr", "GET", getBundleAttrHdrHandler)

	// This route is used to get user attributes header for a tenant
	getTenantRoute("/userattrhdr", "GET", getUserAttrHdrHandler)

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

	// This route is used to get a specific trace request for a tenant
	getTenantRoute("/tracereq/{traceid}", "GET", getTraceReqHandler)

	// This route is used to get all trace requests for a tenant
	getTenantRoute("/alltracereq", "GET", getAllTraceReqHandler)

	// This route is used to get keepalive information for a user
	getTenantRoute("/userstatus/{userid}", "GET", getUserStatus)

	// This route is used to get keepalive information for a user
	getTenantRoute("/bundlestatus/{bid}", "GET", getBundleStatus)

	// This route is used to get all Identity Providers for a tenant
	getTenantRoute("/allidps", "GET", getAllIDPsHandler)

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

	// This route is used by agents & connectors post onboarding, for keepalives.
	// This is kept as a global route and not a per-tenant route (which it can be)
	// because agents coming to us with keepalives will have the lowest of all privileges
	// and might not be able to access the tenant API space
	addGlobalRoute("/keepaliverequest", "POST", keepaliveReqHandler)

	//*******************************************************************/
	//            In Per-tenant DB
	//*******************************************************************/

	// This route is used by the tenant admin to modify the tenant parameters
	addTenantRoute("/tenant", "POST", modifytenantHandler)

	// This route is used by the tenant admin to add a tenant admin group
	addTenantRoute("/admgroups/{group}", "POST", addAdminGroupsHandler)

	// This route is used by the tenant admin to delete a tenant admin group
	delTenantRoute("/admgroups/{group}", "GET", delAdminGroupsHandler)

	// This route is used to add new users with basic user info
	addTenantRoute("/user", "POST", addUserHandler)

	// This route is used to delete users. Both user info and user attribute
	// docs will be deleted for specified user
	delTenantRoute("/user/{userid}", "GET", delUserHandler)

	// This route is used to update/change the group admin role of a user
	addTenantRoute("/user/adminrole/{userid}/{group}", "POST", updUserAdminRole)

	// This route is used to add all possible attributes for users/bundles
	addTenantRoute("/attrset", "POST", addAttrSet)

	// This route is used to delete a set of attributes for users/bundles
	delTenantRoute("/attrset", "POST", delAttrSet)

	// This route is used to add new user attributes header
	addTenantRoute("/userattrhdr", "POST", addUserAttrHdrHandler)

	// This route is used to add bundle attributes header
	addTenantRoute("/bundleattrhdr", "POST", addBundleAttrHdrHandler)

	// This route is used to add host attributes header
	addTenantRoute("/hostattrhdr", "POST", addHostAttrHdrHandler)

	// This route is used to add attributes for a user
	addTenantRoute("/userattr", "POST", addUserAttrHandler)

	// This route is used to update attributes for multiple users
	addTenantRoute("/userattr/multiple", "POST", updMultiUsersAttrHandler)

	// This route is used to add attributes for an app-bundle
	addTenantRoute("/bundleattr", "POST", addBundleAttrHandler)

	// This route is used to add host attributes for a tenant
	addTenantRoute("/hostattr", "POST", addHostAttrHandler)

	// This route is used to add a new app-bundle with basic info
	addTenantRoute("/bundle", "POST", addBundleHandler)

	// This route is used to add a new Identity Provider
	addTenantRoute("/idp", "POST", addIDPHandler)

	// This route is used to delete an Identity Provider
	delTenantRoute("/idp/{name}", "GET", delIDPHandler)

	// This route is used to delete a specific app-bundle
	// Both app-bundle info and app-bundle attribute docs will be deleted
	delTenantRoute("/bundle/{bid}", "GET", delBundleHandler)

	// This route is used to get attributes for a specific host
	delTenantRoute("/hostattr/{host}", "GET", delHostAttrHandler)

	// This route is used to add or update a cluster assignment for a tenant
	addTenantRoute("/tenantcluster", "POST", addTenantClusterHandler)

	// This route is used to delete a cluster assignment for a tenant
	delTenantRoute("/tenantcluster/{gateway}", "GET", delTenantClusterHandler)

	// This route is used to delete an onboarding log entry for a user
	delTenantRoute("/onboardlog/{userid}", "GET", delOnboardLogHandler)

	// This route is used to add a new trace requests header
	addTenantRoute("/tracereqhdr", "POST", addTraceRequestsHdrHandler)

	// This route is used to add a trace request
	addTenantRoute("/tracereq", "POST", addTraceReqHandler)

	// This route is used to delete a trace request
	delTenantRoute("/tracereq/{traceid}", "GET", delTraceReqHandler)
}

const defDevAttrGroup = "admin-secops"

var devAttrs = []db.AttrSet{
	db.AttrSet{Name: "_hostname", AppliesTo: "Users", Type: "String", IsArray: "false", Group: defDevAttrGroup},
	db.AttrSet{Name: "_model", AppliesTo: "Users", Type: "String", IsArray: "false", Group: defDevAttrGroup},
	db.AttrSet{Name: "_osName", AppliesTo: "Users", Type: "String", IsArray: "false", Group: defDevAttrGroup},
	db.AttrSet{Name: "_osType", AppliesTo: "Users", Type: "String", IsArray: "false", Group: defDevAttrGroup},
	db.AttrSet{Name: "_osMajor", AppliesTo: "Users", Type: "Number", IsArray: "false", Group: defDevAttrGroup},
	db.AttrSet{Name: "_osMinor", AppliesTo: "Users", Type: "Number", IsArray: "false", Group: defDevAttrGroup},
	db.AttrSet{Name: "_osPatch", AppliesTo: "Users", Type: "String", IsArray: "false", Group: defDevAttrGroup},
}

func setDeviceAttrSet(tenant string, admin string) error {

	for _, dattr := range devAttrs {
		err := db.DBAddAttrSet(tenant, admin, defDevAttrGroup, dattr, true)
		if err != nil {
			glog.Errorf("setDeviceAttrSet: error adding %s - %v", dattr.Name, err)
		}
	}
	return nil
}
func signupWithIdp(w http.ResponseWriter, tenant string, email string) (string, error) {

	gid, err := IdpAddGroup(API, TOKEN, tenant, true)
	if err != nil {
		errmsg := fmt.Sprintf("Group creation failed for tenant %s - %v", tenant, err)
		return "", errors.New(errmsg)
	}
	uid, err := IdpAddUser(API, TOKEN, email, tenant, "admin", true)
	if err != nil {
		errmsg := "Failure adding user, please try again: " + err.Error()
		return "", errors.New(errmsg)
	}

	err = IdpAddUserToGroup(API, TOKEN, gid, uid, email, true)
	if err != nil {
		errmsg := "Failed to add user to group, please try again: " + err.Error()
		return "", errors.New(errmsg)
	}
	return gid, nil
}

func addBasePolicies(uuid string, user string) error {
	accessPolicy := "package app.access\n\nallow = true\n"
	routePolicy := "package user.routing\n\ndefault route_tag = \"\"\n"
	tracePolicy := "package user.tracing\n\ndefault request = {\"no\": [\"\"]}\n"
	statsPolicy := "package user.stats\n\ndefault attributes = {\"exclude\": [\"uid\", \"maj_ver\", \"min_ver\", \"_hostname\", \"_model\", \"_osMinor\", \"_osPatch\", \"_osName\"]}\n"

	policy := db.Policy{PolicyId: "AccessPolicy", Rego: []rune(accessPolicy)}
	err := db.DBAddPolicy(uuid, user, &policy)
	if err != nil {
		return err
	}
	policy = db.Policy{PolicyId: "RoutePolicy", Rego: []rune(routePolicy)}
	err = db.DBAddPolicy(uuid, user, &policy)
	if err != nil {
		return err
	}
	policy = db.Policy{PolicyId: "TracePolicy", Rego: []rune(tracePolicy)}
	err = db.DBAddPolicy(uuid, user, &policy)
	if err != nil {
		return err
	}
	policy = db.Policy{PolicyId: "StatsPolicy", Rego: []rune(statsPolicy)}
	err = db.DBAddPolicy(uuid, user, &policy)
	if err != nil {
		return err
	}
	return nil
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

	if db.DBFindTenant(signup.Tenant) != nil {
		result.Result = "Enterprise ID already taken, please signup for another enterprise, or contact admin for the enterprise to get you an account in this enterprise"
		utils.WriteResult(w, result)
		return
	}

	gid, gerr := signupWithIdp(w, signup.Tenant, signup.Email)
	if gerr != nil {
		errmsg := fmt.Sprintf("Tenant %s error: %v", signup.Tenant, gerr)
		result.Result = errmsg
		utils.WriteResult(w, result)
		return
	}

	var data db.TenantJson
	data.ID = signup.Tenant
	data.Group = gid
	err = db.DBAddTenant(&data, signup.Email, false)
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

	setDeviceAttrSet(signup.Tenant, signup.Email)

	var user db.User
	user.Uid = signup.Email
	user.Email = signup.Email
	user.Usertype = "admin"
	err = db.DBAddUser(signup.Tenant, user.Uid, &user)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}
	// Add "base" attributes
	err = db.DBAddUserAttr(signup.Tenant, user.Uid, user.Uid, nil)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	err = addBasePolicies(signup.Tenant, user.Uid)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type GetTenantResult struct {
	Result string `json:"Result"`
	Tenant db.Tenant
}

type GetTenantAdminGroupsResult struct {
	Result    string `json:"Result"`
	AdmGroups []string
}

type GetTenantGroupAdminsResult struct {
	Result    string `json:"Result"`
	GrpAdmins []string
}

// Get existing tenant's parameters
func gettenantHandler(w http.ResponseWriter, r *http.Request) {
	var result GetTenantResult

	uuid := r.Context().Value("tenant").(string)
	tenant := db.DBFindTenant(uuid)
	if tenant == nil {
		result.Result = "Tenant not found"
		utils.WriteResult(w, result)
		return
	}
	result.Result = "ok"
	result.Tenant = *tenant
	utils.WriteResult(w, result)
}

// Modify existing tenant's parameters
func modifytenantHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult
	var data db.TenantJson

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
	data.ID = r.Context().Value("tenant").(string)
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}
	err = db.DBAddTenant(&data, admin, true)
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
	var data db.TenantJson

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
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}
	gid, gerr := IdpAddGroup(API, TOKEN, data.ID, false)
	if gerr != nil {
		errmsg := fmt.Sprintf("Group creation failed for tenant %s - %v", data.ID, gerr)
		glog.Errorf(errmsg)
		result.Result = errmsg
		utils.WriteResult(w, result)
		return
	}
	data.Group = gid
	err = db.DBAddTenant(&data, admin, false)
	if err != nil {
		glog.Errorf("DB tenant fail " + err.Error())
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	setDeviceAttrSet(data.ID, admin)

	err = addBasePolicies(data.ID, admin)
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
	err, gws := db.DBFindAllGatewaysForTenant(uuid)
	if err != nil {
		result.Result = "Error fetching gateways: " + err.Error()
		utils.WriteResult(w, result)
		return
	}

	// First get stuff cleaned out from okta, if thats not done we cant
	// delete stuff from our database
	err = IdpDelGroup(API, TOKEN, uuid)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	for _, gw := range gws {
		err := db.DBDelTenantCluster(uuid, db.DBGetClusterName(gw.Name))
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

// Add a tenant's admin group
func addAdminGroupsHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult

	tenant := r.Context().Value("tenant").(string)
	admintype, ok := r.Context().Value("usertype").(string)
	if !ok {
		admintype = "regular"
	}
	v := mux.Vars(r)
	grp := v["group"]
	err := db.DBAddTenantAdminGroup(tenant, admintype, grp)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

// Delete existing tenant's admin group
func delAdminGroupsHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult

	tenant := r.Context().Value("tenant").(string)
	admintype, ok := r.Context().Value("usertype").(string)
	if !ok {
		admintype = "regular"
	}
	v := mux.Vars(r)
	grp := v["group"]
	err := db.DBDelTenantAdminGroup(tenant, admintype, grp)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

// Get tenant's existing admin groups
func getAllAdminGroupsHandler(w http.ResponseWriter, r *http.Request) {
	var result GetTenantAdminGroupsResult

	tenant := r.Context().Value("tenant").(string)
	admgrps := db.DBFindTenantAdminGroups(tenant)
	if admgrps != nil {
		for _, grp := range *admgrps {
			result.AdmGroups = append(result.AdmGroups, grp)
		}
		result.Result = "ok"
		utils.WriteResult(w, result)
		return
	}
	result.Result = "Could not find any admin groups"
	utils.WriteResult(w, result)
}

// This function gets all admins for a specific attributes group
// usertype of admin for the group is obtained by prefixing "admin-" to group.
func getAdminsForGroupHandler(w http.ResponseWriter, r *http.Request) {
	var result GetTenantGroupAdminsResult
	var err error

	tenant := r.Context().Value("tenant").(string)
	admintype, ok := r.Context().Value("usertype").(string)
	if !ok {
		admintype = "regular"
	}
	v := mux.Vars(r)
	grp := v["group"]
	utype := "admin-" + grp

	grpadmin := strings.HasPrefix(admintype, "admin-")
	if (admintype != "superadmin") && (admintype != "admin") && (!grpadmin) {
		glog.Errorf("getAdminsForGroupHandler: Need admin privileges to get group admins")
		result.Result = "Error-NotPrivileged"
		utils.WriteResult(w, result)
		return
	}
	result.GrpAdmins, err = IdpGetUsersByType(API, TOKEN, tenant, utype)
	if err != nil {
		glog.Errorf("getAdminsForGroupHandler: failed to get admins of type %s - %v", utype, err)
		result.Result = "Error-GetFailure"
		utils.WriteResult(w, result)
		return
	}
	result.Result = "ok"
	utils.WriteResult(w, result)
	glog.Infof("getAdminsForGroupHandler: %d admins found with usertype %s in Idp", len(result.GrpAdmins), utype)
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
	Result      string      `json:"Result"`
	Userid      string      `json:"userid"`
	Tenant      string      `json:"tenant"`
	Gateway     string      `json:"gateway"`
	Domains     []db.Domain `json:"domains"`
	Connectid   string      `json:"connectid"`
	Cluster     string      `json:"cluster"`
	Podname     string      `json:"podname"`
	Cacert      []rune      `json:"cacert"`
	Services    []string    `json:"services"`
	Version     string      `json:"version"`
	Keepalive   uint        `json:"keepalive"`
	SplitTunnel bool        `json:"splittunnel"`
}

func onboardHandler(w http.ResponseWriter, r *http.Request) {
	var result OnboardResult
	var data onboardData

	data.Userid = r.Context().Value("userid").(string)
	data.Tenant = r.Context().Value("user-tenant").(string)
	glog.Infof("User/Tenant onboarding - %s/%s", data.Userid, data.Tenant)

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
		result.Version = tenant.ConfigVersion
		result.SplitTunnel = tenant.SplitTunnel
	} else {
		bundle := db.DBFindBundle(data.Tenant, data.Userid)
		if bundle != nil {
			secret := r.Context().Value("secret").(string)
			claims := db.GetMyJwt(bundle.SharedKey)
			if claims == nil {
				result.Result = "Bundle bad secret"
				utils.WriteResult(w, result)
				return
			}
			if secret != claims.Secret {
				result.Result = "Bundle secret mismatch"
				utils.WriteResult(w, result)
				return
			}
			result.Connectid = bundle.Connectid
			if bundle.Pod != "" {
				result.Connectid = bundle.Pod
			}
			result.Services = bundle.Services
			result.Gateway = bundle.Gateway
			result.Cluster = db.DBGetClusterName(bundle.Gateway)
			result.Version = tenant.ConfigVersion
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
	if result.Services == nil {
		result.Services = make([]string, 0)
	}
	result.Result = "ok"
	result.Userid = data.Userid
	result.Tenant = data.Tenant
	result.Cacert = cert.Cert
	result.Domains = db.ProcessDomains(tenant.Domains)
	if result.Domains == nil {
		result.Domains = make([]db.Domain, 0)
	}
	result.Keepalive = 30 /* 30 seconds */

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

type KeepaliveResponse struct {
	Result  string `json:"Result"`
	Version string `json:"version"`
}

// TODO: WILL BE DEPRECATED
func keepaliveHandler(w http.ResponseWriter, r *http.Request) {
	var result KeepaliveResponse

	v := mux.Vars(r)
	version := v["version"]
	uuid := v["uuid"]
	userid := r.Context().Value("userid").(string)
	tenant := r.Context().Value("user-tenant").(string)
	glog.Error("USer/Tenant keepalive", userid, uuid, tenant, version)

	t := db.DBFindTenant(tenant)
	if t == nil {
		result.Result = "Tenant not found"
		utils.WriteResult(w, result)
		return
	}
	result.Version = t.ConfigVersion
	user := db.DBFindUser(tenant, userid)
	if user == nil {
		bundle := db.DBFindBundle(tenant, userid)
		if bundle == nil {
			result.Result = "IDP user/bundle not found on controller"
			utils.WriteResult(w, result)
			return
		}
	}
	result.Result = "ok"
	utils.WriteResult(w, result)
}

// TODO NOTE: THIS will be the biggest scale bottleneck for the controller
// Tens of thousands of devices keepalive requesting will kill the controller
// So we will need to find some alternative way of handling this, like split
// the keepalive database into a seperate one (per tenant of course) and then
// spread it across multiple controllers so each controller handles a set of
// tenants and their keepalive database writes.
func keepaliveReqHandler(w http.ResponseWriter, r *http.Request) {
	var result KeepaliveResponse
	var data db.Keepalive

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Keepalive - HTTP Req Read fail"
		utils.WriteResult(w, result)
		return
	}
	err = json.Unmarshal(body, &data)
	if err != nil {
		result.Result = "Keepalive - Error parsing json"
		utils.WriteResult(w, result)
		return
	}
	data.Seen = time.Now().Unix()

	userid := r.Context().Value("userid").(string)
	tenant := r.Context().Value("user-tenant").(string)

	t := db.DBFindTenant(tenant)
	if t == nil {
		result.Result = "Tenant not found"
		utils.WriteResult(w, result)
		return
	}
	result.Version = t.ConfigVersion
	user := db.DBFindUser(tenant, userid)
	if user != nil {
		// We dont check the keepalive return value, keepalives are sent periodically
		db.UserKeepalive(tenant, user, data)
	} else {
		bundle := db.DBFindBundle(tenant, userid)
		if bundle == nil {
			result.Result = "IDP user/bundle not found on controller"
			utils.WriteResult(w, result)
			return
		}
		// We dont check the keepalive return value, keepalives are sent periodically
		db.BundleKeepalive(tenant, bundle, data)
	}
	result.Result = "ok"
	utils.WriteResult(w, result)
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
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}

	idpgid, err := IdpGetGroupID(API, TOKEN, uuid)
	if err != nil {
		result.Result = "Multiple groups found for tenant " + uuid + " - " + err.Error()
		utils.WriteResult(w, result)
		return
	}
	usertype := "regular"
	if data.Usertype == "" {
		data.Usertype = usertype
	} else {
		usertype = data.Usertype
	}
	idpuser, err := IdpAddUser(API, TOKEN, data.Uid, uuid, usertype, false)
	if err != nil {
		msg := "Adding user to IDP fail:" + err.Error()
		glog.Errorf(msg)
		result.Result = msg
		utils.WriteResult(w, result)
		return
	}
	err = IdpAddUserToGroup(API, TOKEN, idpgid, idpuser, data.Uid, false)
	if err != nil {
		glog.Errorf("IdpAddUserToGroup failed for user %s in group %s - %v", data.Uid, uuid, err)
		result.Result = "Failed to add user to group, please try again: " + err.Error()
		utils.WriteResult(w, result)
		return
	}

	err = db.DBAddUser(uuid, admin, &data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}
	// Add/Update base attributes
	err = db.DBAddUserAttr(uuid, admin, data.Uid, nil)
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
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}

	err := IdpDelUser(API, TOKEN, userid, uuid)
	if err != nil {
		result.Result = "Deleting user from IDP fail: " + err.Error()
		utils.WriteResult(w, result)
		return
	}

	err = db.DBDelUserAttr(uuid, admin, userid)
	if err != nil {
		result.Result = err.Error()
	} else {
		err = db.DBDelUser(uuid, admin, userid)
		if err != nil {
			result.Result = err.Error()
		} else {
			result.Result = "ok"
		}
	}
	utils.WriteResult(w, result)
}

// Get all attribute sets
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

type GetAdminRoleResult struct {
	UserRole string `json:"UserRole"`
}

// Get usertype of a specific user
func getUserAdminRole(w http.ResponseWriter, r *http.Request) {
	var result GetAdminRoleResult

	tenant := r.Context().Value("tenant").(string)
	admingrp, ok := r.Context().Value("usertype").(string)
	if !ok {
		admingrp = "regular"
	}
	v := mux.Vars(r)
	uid := v["userid"]
	if (admingrp != "superadmin") && (!strings.HasPrefix(admingrp, "admin-")) {
		glog.Errorf("getUserAdminRole: Need admin privileges to get user type")
		result.UserRole = "Error-NotPrivileged"
		utils.WriteResult(w, result)
		return
	}
	_, idpTenant, usertype, err := IdpGetUserInfo(API, TOKEN, uid)
	if err != nil {
		glog.Errorf("getUserAdminRole: user %s info not found in Idp - %v", uid, err)
		result.UserRole = "Error-UnknownUser"
		utils.WriteResult(w, result)
		return
	}
	if idpTenant != tenant {
		glog.Errorf("getUserAdminRole: user tenant mismatch - %s v/s %s", tenant, idpTenant)
		result.UserRole = "Error-TenantMismatch"
		utils.WriteResult(w, result)
		return
	}
	result.UserRole = usertype
	utils.WriteResult(w, result)
}

// Set admin role of a group for any user. Can only be done by the
// superadmin or another admin for the target group. Can also remove
// a user from group admin role to be a regular user.
// Attempts to upgrade to or downgrade from superadmin not allowed here.
// Involves setting usertype for user in Okta.
func updUserAdminRole(w http.ResponseWriter, r *http.Request) {
	var result OpResult
	tenant := r.Context().Value("tenant").(string)
	admingrp, ok := r.Context().Value("usertype").(string)
	if !ok {
		admingrp = "regular"
	}
	v := mux.Vars(r)
	uid := v["userid"]
	// group is tenant defined. We prefix "admin-" to it when setting usertype.
	grp := v["group"]
	if (admingrp != "superadmin") && (!strings.HasPrefix(admingrp, "admin-")) {
		glog.Errorf("updUserAdminRole: Need admin privileges to change user type")
		result.Result = " Need admin privileges to change user type"
		utils.WriteResult(w, result)
		return
	}
	if admingrp != "superadmin" {
		splitg := strings.SplitN(admingrp, "-", 2)
		if splitg[1] != grp {
			glog.Errorf("updUserAdminRole: %s cannot set admin role for %s", admingrp, grp)
			result.Result = admingrp + " cannot set admin role for " + grp
			utils.WriteResult(w, result)
			return
		}
	}
	_, idpTenant, utype, err := IdpGetUserInfo(API, TOKEN, uid)
	if err != nil {
		glog.Errorf("updUserAdminRole: user %s info not found in Idp - %v", uid, err)
		result.Result = "User info not found in Idp"
		utils.WriteResult(w, result)
		return
	}
	if idpTenant != tenant {
		glog.Errorf("updUserAdminRole: user tenant mismatch - %s v/s %s", tenant, idpTenant)
		result.Result = "User tenant mismatch"
		utils.WriteResult(w, result)
		return
	}
	if utype == "superadmin" {
		glog.Errorf("updUserAdminRole: cannot change superadmin usertype")
		result.Result = "User is superadmin. Cannot change usertype"
		utils.WriteResult(w, result)
		return
	}
	grp = "admin-" + grp
	_, err = IdpAddUser(API, TOKEN, uid, tenant, grp, false)
	if err != nil {
		glog.Errorf("updUserAdminRole: user admin role update failed - %v", err)
		result.Result = "User admin role update failed"
		utils.WriteResult(w, result)
		return
	}
	result.Result = "ok"
	utils.WriteResult(w, result)
}

// Get attribute sets for specified type - "Users", "Bundles", "Hosts"
func getSpecificAttrSet(w http.ResponseWriter, r *http.Request) {
	uuid := r.Context().Value("tenant").(string)
	admingrp, ok := r.Context().Value("usertype").(string)
	if !ok {
		admingrp = "regular"
	}
	v := mux.Vars(r)
	atyp := v["type"]
	set := db.DBFindSpecificAttrSet(uuid, atyp, admingrp)
	if set == nil {
		result := make([]db.AttrSet, 0)
		utils.WriteResult(w, result)
	} else {
		result := set
		utils.WriteResult(w, result)
	}
}

// Add a tenants attribute set
func addAttrSet(w http.ResponseWriter, r *http.Request) {
	var result OpResult
	var data db.AttrSet

	uuid := r.Context().Value("tenant").(string)
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}
	admingrp, ok := r.Context().Value("usertype").(string)
	if !ok {
		admingrp = "regular"
	}
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
	err = db.DBAddAttrSet(uuid, admin, admingrp, data, false)
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
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}
	admingrp, ok := r.Context().Value("usertype").(string)
	if !ok {
		admingrp = "regular"
	}
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
	err = db.DBDelAttrSet(uuid, admin, admingrp, data)
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
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}
	err = db.DBAddUserAttrHdr(uuid, admin, &data)
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
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}
	err = db.DBAddUserAttr(uuid, admin, user, Uattr)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

func updMultiUsersAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Update Multi-User attributes - HTTP Req Read fail"
		utils.WriteResult(w, result)
		return
	}

	var Uattr []bson.M
	err = json.Unmarshal(body, &Uattr)
	if err != nil {
		result.Result = "Users json decode fail"
		utils.WriteResult(w, result)
		return
	}
	uuid := r.Context().Value("tenant").(string)
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}
	err = db.DBUpdateAttrsForMultipleUsers(uuid, admin, Uattr)
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
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}
	err = db.DBAddBundle(uuid, admin, &data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}
	// Add/update "base" attributes
	err = db.DBAddBundleAttr(uuid, admin, data.Bid, nil)
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
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}

	err := db.DBDelBundleAttr(uuid, admin, bid)
	if err != nil {
		result.Result = err.Error()
	} else {
		err = db.DBDelBundle(uuid, admin, bid)
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
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}
	err = db.DBAddBundleAttrHdr(uuid, admin, &data)
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
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}
	err = db.DBAddBundleAttr(uuid, admin, bid, Battr)
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
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}
	err = db.DBAddHostAttrHdr(uuid, admin, &data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

// Add a host's attribute, used to decide what policies are applied to host routing
func addHostAttrHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Add Host attributes - HTTP Req Read fail"
		utils.WriteResult(w, result)
		return
	}
	uuid := r.Context().Value("tenant").(string)
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}
	err = db.DBAddHostAttr(uuid, admin, body)
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
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}
	err := db.DBDelHostAttr(uuid, admin, host)
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

type GetTraceReqResult struct {
	Result string `json:"Result"`
	TrReq  bson.M
}

// Get a trace request
func getTraceReqHandler(w http.ResponseWriter, r *http.Request) {
	var result GetTraceReqResult

	v := mux.Vars(r)
	traceid := v["traceid"]
	uuid := r.Context().Value("tenant").(string)
	treq := db.DBFindUserAttr(uuid, traceid)
	if treq == nil {
		result.Result = "Cannot find trace request"
	} else {
		result = GetTraceReqResult{Result: "ok", TrReq: *treq}
	}
	utils.WriteResult(w, result)
}

// Get all trace request docs
func getAllTraceReqHandler(w http.ResponseWriter, r *http.Request) {
	uuid := r.Context().Value("tenant").(string)
	treqs := db.DBFindAllTraceReqs(uuid)
	if treqs == nil {
		treqs = make([]bson.M, 0)
	}
	utils.WriteResult(w, treqs)

}

// Add a trace requests collection header
func addTraceRequestsHdrHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult
	var data db.DataHdr

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Add trace request header - HTTP Req Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		result.Result = "Add trace request header - Error parsing json"
		utils.WriteResult(w, result)
		return
	}
	uuid := r.Context().Value("tenant").(string)
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}
	err = db.DBAddTraceRequestsHdr(uuid, admin, &data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

// Add a trace request
func addTraceReqHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Add trace request - HTTP Req Read fail"
		utils.WriteResult(w, result)
		return
	}

	var Treq bson.M
	var traceid string
	err = json.Unmarshal(body, &Treq)
	if err != nil {
		result.Result = "Trace request json decode fail"
		utils.WriteResult(w, result)
		return
	}
	if v, found := Treq["traceid"]; found {
		traceid = fmt.Sprintf("%s", v)
		delete(Treq, "traceid")
	} else {
		result.Result = "Missing trace id"
		utils.WriteResult(w, result)
		return
	}
	uuid := r.Context().Value("tenant").(string)
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}
	err = db.DBAddTraceReq(uuid, admin, traceid, Treq)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

// Delete a trace request
func delTraceReqHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult

	v := mux.Vars(r)
	traceid := v["traceid"]
	uuid := r.Context().Value("tenant").(string)
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}

	err := db.DBDelTraceReq(uuid, admin, traceid)
	if err != nil {
		result.Result = err.Error()
	} else {
		result.Result = "ok"
	}
	utils.WriteResult(w, result)
}

// Get details about user devices and their status
func getUserStatus(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	userid := v["userid"]
	uuid := r.Context().Value("tenant").(string)
	result := db.DBFindUserStatus(uuid, userid)
	utils.WriteResult(w, result)
}

// Get details about bundles and their status
func getBundleStatus(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	bid := v["bid"]
	uuid := r.Context().Value("tenant").(string)
	result := db.DBFindBundleStatus(uuid, bid)
	utils.WriteResult(w, result)
}

func addIDPHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult
	var data db.IDP

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Add IDP info - Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		result.Result = "Add IDP info - Error parsing json"
		utils.WriteResult(w, result)
		return
	}

	uuid := r.Context().Value("tenant").(string)
	tenant := db.DBFindTenant(uuid)
	if tenant == nil {
		result.Result = "Cant find tenant: " + uuid
		utils.WriteResult(w, result)
		return
	}

	// To make sure the names are unique in okta, prefix the tenant name
	origName := data.Name
	data.Name = tenant.Name + "-" + data.Name
	data.Group = tenant.Group
	ierr := okta.CreateIDP(API, TOKEN, &data)
	if ierr != nil {
		result.Result = ierr.Error()
		utils.WriteResult(w, result)
		return
	}

	// In our own DB we just create the name without tenant prefix
	data.Name = origName
	err = db.DBaddTenantIdp(tenant, data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

func delIDPHandler(w http.ResponseWriter, r *http.Request) {
	var result OpResult

	v := mux.Vars(r)
	name := v["name"]
	uuid := r.Context().Value("tenant").(string)
	tenant := db.DBFindTenant(uuid)
	if tenant == nil {
		result.Result = "Cant find tenant: " + uuid
		utils.WriteResult(w, result)
		return
	}
	for _, idp := range tenant.Idps {
		if idp.Name == name {
			err := okta.DeleteIDP(API, TOKEN, &idp)
			if err != nil {
				result.Result = err.Error()
				utils.WriteResult(w, result)
				return
			}
			err = db.DBdelTenantIDP(tenant, name)
			if err != nil {
				result.Result = err.Error()
				utils.WriteResult(w, result)
				return
			}
			break
		}
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

func getAllIDPsHandler(w http.ResponseWriter, r *http.Request) {
	uuid := r.Context().Value("tenant").(string)
	tenant := db.DBFindTenant(uuid)
	if tenant == nil {
		var result OpResult
		result.Result = "Cant find tenant: " + uuid
		utils.WriteResult(w, result)
		return
	}

	utils.WriteResult(w, tenant.Idps)
}
