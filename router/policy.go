package router

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"nextensio/controller/db"
	"nextensio/controller/utils"

	"github.com/golang/glog"
	"github.com/gorilla/mux"
)

func rdonlyPolicy() {
	// This route is used to retrieve a policy in a tenant
	getTenantRoute("/policy/{policy-id}", "GET", getpolicyHandler)

	// This route is used to get all policies
	getTenantRoute("/allpolicies", "GET", getAllPoliciesHandler)

	// This route is used to get all rules for one bundle or all bundles
	// {bid} = "all" for all bundles
	getTenantRoute("/bundlerules/{bid}", "GET", getBundleAllRulesHandler)

	// This route is used to get a specific bundle rule
	getTenantRoute("/bundlerule/{bid}/{ruleid}", "GET", getBundleRuleHandler)

	// This route is used to get all rules for one host or all hosts
	// {hostid} = "all" for all hosts
	getTenantRoute("/hostrules/{hostid}", "GET", getHostAllRulesHandler)

	// This route is used to get a specific host rule
	getTenantRoute("/hostrule/{hostid}/{ruleid}", "GET", getHostRuleHandler)

	// This route is used to get the rule for one trace req or all trace reqs
	// {traceid} = "all" for all trace reqs
	getTenantRoute("/tracereqrules/{traceid}", "GET", getTraceReqRuleHandler)

	// This route is used to get a complete stats rule (there is only one).
	getTenantRoute("/statsrule", "GET", getAllStatsRulesHandler)
}

func rdwrPolicy() {
	// This route is used by the tenant admin to add a new OPA policy
	addTenantRoute("/policy", "POST", addpolicyHandler)

	// This route is used by the tenant admin to generate a new OPA policy
	// in Easy Mode from configured rules
	// {policy-id} = "AccessPolicy" | "RoutePolicy" | "TracePolicy" | "StatsPolicy"
	addTenantRoute("/policy/generate/{policy-id}", "POST", addPolicyFromRulesHandler)

	// This route is used by the tenant admin to delete an OPA policy
	delTenantRoute("/policy/{policy-id}", "GET", delpolicyHandler)

	// This route is used by the tenant admin to add a new bundle ID sub-rule
	// for a group (or update an existing one). The json body contains the
	// details such as bid, rid, group and sub-rules.
	addTenantRoute("/bundlerule", "POST", addBundleRuleHandler)

	// This route is used by an admin to delete bundle rule expressions for a group
	delTenantRoute("/bundlerule/{bid}/{rid}/{group}", "GET", delBundleRuleGroupHandler)

	// This route is used by the tenant admin to add a new host ID sub-rule
	// for a group (or update an existing one). The json body contains the
	// details such as host, rid, group and sub-rules.
	addTenantRoute("/hostrule/", "POST", addHostRuleGroupHandler)

	// This route is used by the tenant admin to delete a host ID group sub-rule
	delTenantRoute("/hostrule/{host}/{rid}/{group}", "GET", delHostRuleGroupHandler)

	// This route is used by an admin to add a new trace req sub-rule for a group
	// (or update an existing one). The json body contains the
	// details such as traceid, group and sub-rules.
	addTenantRoute("/tracereqrule", "POST", addTraceReqRuleGroupHandler)

	// This route is used by the tenant admin to delete a trace req group sub-rule
	delTenantRoute("/tracereqrule/{rid}/{group}", "GET", delTraceReqRuleGroupHandler)

	// This route is used by the an admin to add/update a new stats sub-rule for
	// a group. The sub-rule contains the user attributes owned by the group
	addTenantRoute("/statsrule", "POST", addStatsRuleGroupHandler)

	// This route is used by the tenant admin to delete a stats sub-rule owned by
	// the group.
	delTenantRoute("/statsrule/{group}", "GET", delStatsRuleGroupHandler)
}

type AddpolicyResult struct {
	Result string `json:"Result"`
}

// Add a new OPA policy
func addpolicyHandler(w http.ResponseWriter, r *http.Request) {
	var result AddpolicyResult
	var data db.Policy

	if !allowTenantAdminOnly(r) {
		result.Result = "Not privileged to add a policy"
		utils.WriteResult(w, result)
		return
	}

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
	uuid := r.Context().Value("tenant").(string)
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}
	err = db.DBAddPolicy(uuid, admin, &data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

func addPolicyFromRulesHandler(w http.ResponseWriter, r *http.Request) {
	var result AddpolicyResult

	uuid := r.Context().Value("tenant").(string)
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}
	v := mux.Vars(r)
	pid := v["policy-id"]
	err := db.DBGeneratePolicyFromRules(uuid, pid, admin)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type GetpolicyResult struct {
	Result string `json:"Result"`
	db.Policy
}

// Get an OPA policy
func getpolicyHandler(w http.ResponseWriter, r *http.Request) {
	var result GetpolicyResult

	v := mux.Vars(r)
	pid := v["policy-id"]
	uuid := r.Context().Value("tenant").(string)
	policy := db.DBFindPolicy(uuid, pid)
	if policy == nil {
		result.Result = "Cannot find policy"
	} else {
		result = GetpolicyResult{Result: "ok", Policy: *policy}
	}
	utils.WriteResult(w, result)
}

// Get all policies
func getAllPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	uuid := r.Context().Value("tenant").(string)
	policies := db.DBFindAllPolicies(uuid)
	if policies == nil {
		policies = make([]db.Policy, 0)
	}
	utils.WriteResult(w, policies)

}

type DelpolicyResult struct {
	Result string `json:"Result"`
}

// Delete an OPA policy
func delpolicyHandler(w http.ResponseWriter, r *http.Request) {
	var result DelpolicyResult

	if !allowTenantAdminOnly(r) {
		result.Result = "Not privileged to delete a policy"
		utils.WriteResult(w, result)
		return
	}

	v := mux.Vars(r)
	pid := v["policy-id"]
	uuid := r.Context().Value("tenant").(string)
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}
	err := db.DBDelPolicy(uuid, admin, pid)
	if err != nil {
		result.Result = err.Error()
	} else {
		result = DelpolicyResult{Result: "ok"}
	}
	utils.WriteResult(w, result)
}

// Rules, rules and rules !
//---------------------Bundle, Host, Trace Req aand Stats rules--------------------

type RuleOpResult struct {
	Result string `json:"Result"`
}

// Common function to add sub-rules for a group, whether it be for bundles,
// hosts, trace reqs, or stats.
func addRuleGenericHandler(w http.ResponseWriter, r *http.Request, ruletype string) {
	var result RuleOpResult

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Read fail"
		utils.WriteResult(w, result)
		return
	}

	uuid := r.Context().Value("tenant").(string)
	admin, ok := r.Context().Value("userid").(string)
	if !ok {
		admin = "UnknownUser"
	}
	usertype, ok := r.Context().Value("usertype").(string)
	if !ok {
		usertype = "regular"
	}
	group, ok := r.Context().Value("group").(string)
	if !ok {
		group = usertype
	}
	glog.Infof("Add%sRule: Adding group rule %v", ruletype, body)
	var aerr error
	switch ruletype {
	case "AppGroup":
		aerr = db.DBAddBundleRuleGroup(uuid, group, admin, &body)
	case "App":
		aerr = db.DBAddHostRuleGroup(uuid, group, admin, &body)
	case "Trace":
		aerr = db.DBAddTraceReqRuleGroup(uuid, group, admin, &body)
	case "Stats":
		aerr = db.DBAddStatsRuleGroup(uuid, group, admin, &body)
	default:
		aerr = fmt.Errorf("Add%sRule: Unknown rule type", ruletype)
	}
	if aerr != nil {
		glog.Errorf("Add%sRule: error - %v", ruletype, aerr)
		result.Result = aerr.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

// {"bid": "<value>", "rid": "<value>", "group": {Group}, "rule":
//      [ ["lefttoken", "operator", "righttoken", "type", "isArray"],
//        ["lefttoken", "operator", "righttoken", "type", "isArray"],
//        [ ... ]
//      ]
// Add a new bundle ID rule
func addBundleRuleHandler(w http.ResponseWriter, r *http.Request) {

	addRuleGenericHandler(w, r, "AppGroup")
}

func getBundleRuleHandler(w http.ResponseWriter, r *http.Request) {
	uuid := r.Context().Value("tenant").(string)
	v := mux.Vars(r)
	bid := v["bid"]
	ruleid := v["ruleid"]
	brule := db.DBFindBundleRules(uuid, bid, ruleid)
	if brule == nil {
		brule = []db.BundleAccessRule{}
	}
	utils.WriteResult(w, brule)
}

// Get all bundle rules
func getBundleAllRulesHandler(w http.ResponseWriter, r *http.Request) {
	uuid := r.Context().Value("tenant").(string)
	v := mux.Vars(r)
	bid := v["bid"]
	rules := db.DBFindBundleRules(uuid, bid, "")
	if rules == nil {
		rules = []db.BundleAccessRule{}
	}
	utils.WriteResult(w, rules)
}

// Delete a bundle ID sub-rule
func delBundleRuleGroupHandler(w http.ResponseWriter, r *http.Request) {
	var result RuleOpResult

	usertype, ok := r.Context().Value("usertype").(string)
	if !ok {
		usertype = "regular"
	}
	group, ok := r.Context().Value("group").(string)
	if !ok {
		group = usertype
	}
	v := mux.Vars(r)
	bid := v["bid"]
	ruleid := v["rid"]
	grp := v["group"]
	if grp != group {
		// someone is trying to delete some other group's rule expressions
		result.Result = "Group admin mismatch for rule components being deleted"
		utils.WriteResult(w, result)
		return
	}
	uuid := r.Context().Value("tenant").(string)
	err := db.DBDelBundleRuleGroup(uuid, bid, ruleid, group)
	if err != nil {
		result.Result = err.Error()
	} else {
		result = RuleOpResult{Result: "ok"}
	}
	utils.WriteResult(w, result)
}

// {"host": "<value>", "rid": "<value>", "group": {Group}, "rule":
//      [ ["lefttoken", "operator", "righttoken", "type", "isArray"],
//        ["lefttoken", "operator", "righttoken", "type", "isArray"],
//        [ ... ]
//      ]
// Add a new host ID rule portion for a group
func addHostRuleGroupHandler(w http.ResponseWriter, r *http.Request) {

	addRuleGenericHandler(w, r, "App")
}

func getHostRuleHandler(w http.ResponseWriter, r *http.Request) {
	uuid := r.Context().Value("tenant").(string)
	v := mux.Vars(r)
	hostid := v["hostid"]
	ruleid := v["ruleid"]
	hrule := db.DBFindHostRules(uuid, hostid, ruleid)
	if hrule == nil {
		hrule = []db.HostRouteRule{}
	}
	utils.WriteResult(w, hrule)
}

// Get all host rules
func getHostAllRulesHandler(w http.ResponseWriter, r *http.Request) {
	uuid := r.Context().Value("tenant").(string)
	v := mux.Vars(r)
	hostid := v["hostid"]
	rules := db.DBFindHostRules(uuid, hostid, "")
	if rules == nil {
		rules = []db.HostRouteRule{}
	}
	utils.WriteResult(w, rules)
}

// Delete a host ID sub-rule
func delHostRuleGroupHandler(w http.ResponseWriter, r *http.Request) {
	var result RuleOpResult

	usertype, ok := r.Context().Value("usertype").(string)
	if !ok {
		usertype = "regular"
	}
	group, ok := r.Context().Value("group").(string)
	if !ok {
		group = usertype
	}
	v := mux.Vars(r)
	hostid := v["host"]
	ruleid := v["rid"]
	grp := v["group"]
	if grp != group {
		// someone is trying to delete some other group's rule expressions
		result.Result = "Group admin mismatch for rule components being deleted"
		utils.WriteResult(w, result)
		return
	}
	uuid := r.Context().Value("tenant").(string)
	err := db.DBDelHostRuleGroup(uuid, hostid, ruleid, group)
	if err != nil {
		result.Result = err.Error()
	} else {
		result = RuleOpResult{Result: "ok"}
	}
	utils.WriteResult(w, result)
}

// {"rid": "<value>", "group": {Group}, "rule":
//      [ ["lefttoken", "operator", "righttoken", "type", "isArray"],
//        ["lefttoken", "operator", "righttoken", "type", "isArray"],
//        [ ... ]
//      ]
// Rule ID is also the trace request ID (has to be unique)
// {Group} is the admin group owning the user attributes selected
// Add a new trace req rule portion for a group
func addTraceReqRuleGroupHandler(w http.ResponseWriter, r *http.Request) {

	addRuleGenericHandler(w, r, "Trace")
}

func getTraceReqRuleHandler(w http.ResponseWriter, r *http.Request) {
	uuid := r.Context().Value("tenant").(string)
	v := mux.Vars(r)
	traceid := v["traceid"]
	trule := db.DBFindTraceReqRules(uuid, traceid)
	if trule == nil {
		trule = []db.TraceReqRule{}
	}
	utils.WriteResult(w, trule)
}

// Delete a trace req rule
func delTraceReqRuleGroupHandler(w http.ResponseWriter, r *http.Request) {
	var result RuleOpResult

	usertype, ok := r.Context().Value("usertype").(string)
	if !ok {
		usertype = "regular"
	}
	group, ok := r.Context().Value("group").(string)
	if !ok {
		group = usertype
	}
	v := mux.Vars(r)
	ruleid := v["rid"]
	grp := v["group"]
	if grp != group {
		// someone is trying to delete some other group's rule expressions
		result.Result = "Group admin mismatch for rule components being deleted"
		utils.WriteResult(w, result)
		return
	}
	uuid := r.Context().Value("tenant").(string)
	err := db.DBDelTraceReqRuleGroup(uuid, ruleid, group)
	if err != nil {
		result.Result = err.Error()
	} else {
		result = RuleOpResult{Result: "ok"}
	}
	utils.WriteResult(w, result)
}

// {"rid": "StatsRule", "group": {Group}, "rule":
//      [ ["lefttoken", "operator", "righttoken", "type", "isArray"]
//      ]
// Rule ID is constant
// Group depends on the group admin adding the user attributes for the group
// Add a new stats rule portion for a group
func addStatsRuleGroupHandler(w http.ResponseWriter, r *http.Request) {

	addRuleGenericHandler(w, r, "Stats")
}

type GetStatsRuleResult struct {
	Result string `json:"Result"`
	db.StatsRule
}

// Get stats rule
func getAllStatsRulesHandler(w http.ResponseWriter, r *http.Request) {
	uuid := r.Context().Value("tenant").(string)
	rule := db.DBFindStatsRule(uuid)
	if rule == nil {
		rule = make([]db.StatsRule, 0)
	}
	utils.WriteResult(w, rule)

}

// Delete a stats sub-rule
func delStatsRuleGroupHandler(w http.ResponseWriter, r *http.Request) {
	var result RuleOpResult

	usertype, ok := r.Context().Value("usertype").(string)
	if !ok {
		usertype = "regular"
	}
	group, ok := r.Context().Value("group").(string)
	if !ok {
		group = usertype
	}
	v := mux.Vars(r)
	grp := v["group"]
	if grp != group {
		// someone is trying to delete some other group's rule expressions
		result.Result = "Group admin mismatch for rule components being deleted"
		utils.WriteResult(w, result)
		return
	}
	uuid := r.Context().Value("tenant").(string)
	err := db.DBDelStatsRuleGroup(uuid, group)
	if err != nil {
		result.Result = err.Error()
	} else {
		result = RuleOpResult{Result: "ok"}
	}
	utils.WriteResult(w, result)
}
