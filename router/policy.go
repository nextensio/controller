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
	// {bid} == "all" for all bundles
	getTenantRoute("/bundlerules/{bid}", "GET", getBundleAllRulesHandler)

	// This route is used to get a group's match expressions in a bundle rule
	getTenantRoute("/bundlerule/{bid}/{ruleid}", "GET", getBundleRuleHandler)

	// This route is used to get all host rules
	getTenantRoute("/allhostrules", "GET", getAllHostRulesHandler)

	// This route is used to get all trace req rules
	getTenantRoute("/alltracereqrules", "GET", getAllTraceReqRulesHandler)

	// This route is used to get stats rule
	getTenantRoute("/statsrule", "GET", getAllStatsRulesHandler)
}

func rdwrPolicy() {
	// This route is used by the tenant admin to add a new OPA policy
	addTenantRoute("/policy", "POST", addpolicyHandler)

	// This route is used by the tenant admin to generate a new OPA policy
	// in Easy Mode from configured rules
	addTenantRoute("/policy/generate/{policy-id}", "POST", addPolicyFromRulesHandler)

	// This route is used by the tenant admin to delete an OPA policy
	delTenantRoute("/policy/{policy-id}", "GET", delpolicyHandler)

	// This route is used by the tenant admin to add a new bundle ID rule
	addTenantRoute("/bundlerule/", "POST", addBundleRuleHandler)

	// This route is used by an admin to delete a bundle rule expressions
	delTenantRoute("/bundlerule/{bid}/{rid}/{group}", "GET", delBundleRuleGroupHandler)

	// This route is used by the tenant admin to add a new host ID rule
	addTenantRoute("/hostrule/", "POST", addHostRuleHandler)

	addTenantRoute("/lockhostrule/", "POST", lockHostRuleHandler)

	// This route is used by the tenant admin to delete a host ID rule
	delTenantRoute("/hostrule/{host}/{rid}", "GET", delHostRuleHandler)

	// This route is used by the tenant admin to add a new trace req rule
	addTenantRoute("/tracereqrule/", "POST", addTraceReqRuleHandler)

	// This route is used by the tenant admin to delete a trace req rule
	delTenantRoute("/tracereqrule/{rid}", "GET", delTraceReqRuleHandler)

	// This route is used by the tenant admin to add a new statsq rule
	addTenantRoute("/statsrule/", "POST", addStatsRuleHandler)

	// This route is used by the tenant admin to delete a stats rule
	delTenantRoute("/statsrule/{rid}", "GET", delStatsRuleHandler)
}

type AddpolicyResult struct {
	Result string `json:"Result"`
}

// Add a new OPA policy
func addpolicyHandler(w http.ResponseWriter, r *http.Request) {
	var result AddpolicyResult
	var data db.Policy

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

	v := mux.Vars(r)
	pid := v["policy-id"]
	uuid := r.Context().Value("tenant").(string)
	err := db.DBDelPolicy(uuid, pid)
	if err != nil {
		result.Result = err.Error()
	} else {
		result = DelpolicyResult{Result: "ok"}
	}
	utils.WriteResult(w, result)
}

//------------------------------------Bundle, Host and Trace Req rules------------------------------

type RuleOpResult struct {
	Result string `json:"Result"`
}

// {"bid": "<value>", "rid": "<value>", "rule":
//      [ ["lefttoken", "operator", "righttoken", "type", "isArray"],
//        ["lefttoken", "operator", "righttoken", "type", "isArray"],
//        [ ... ]
//      ]
// Add a new bundle ID rule
func addBundleRuleHandler(w http.ResponseWriter, r *http.Request) {
	var result RuleOpResult
	var data db.BundleAccessRule

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		fmt.Println(err)
		result.Result = fmt.Sprintf("%v", err)
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
	if data.Group == "" {
		data.Group = group
	}
	data.Admin = admin
	glog.Infof("AddBundleRule: Adding group rule %v", data)
	err = db.DBAddBundleRuleGroup(uuid, group, &data)
	if err != nil {
		glog.Errorf("AddBundleRule: error - %v", err)
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

func getBundleRuleHandler(w http.ResponseWriter, r *http.Request) {
	uuid := r.Context().Value("tenant").(string)
	v := mux.Vars(r)
	bid := v["bid"]
	ruleid := v["rid"]
	brule := db.DBFindAllGroupsForBundleRule(uuid, bid, ruleid)
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
	rules := db.DBFindBundleAllRules(uuid, bid)
	if rules == nil {
		rules = make([]db.BundleAccessRule, 0)
	}
	utils.WriteResult(w, rules)
}

// Delete a bundle ID rule
func delBundleRuleGroupHandler(w http.ResponseWriter, r *http.Request) {
	var result RuleOpResult

	usertype, ok := r.Context().Value("usertype").(string)
	if !ok {
		usertype = "admin"
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

// {"host": "<value>", "rid": "<value>", "rule":
//      [ ["lefttoken", "operator", "righttoken", "type", "isArray"],
//        ["lefttoken", "operator", "righttoken", "type", "isArray"],
//        [ ... ]
//      ]
// Add a new host ID rule
func addHostRuleHandler(w http.ResponseWriter, r *http.Request) {
	var result RuleOpResult
	var data db.HostRouteRule

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		fmt.Println(err)
		result.Result = fmt.Sprintf("%v", err)
		utils.WriteResult(w, result)
		return
	}
	uuid := r.Context().Value("tenant").(string)
	group := r.Context().Value("group").(string)
	err = db.DBAddHostRule(uuid, group, &data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

func lockHostRuleHandler(w http.ResponseWriter, r *http.Request) {
	var result RuleOpResult
	var data db.LockHostRouteRule

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		fmt.Println(err)
		result.Result = fmt.Sprintf("%v", err)
		utils.WriteResult(w, result)
		return
	}
	uuid := r.Context().Value("tenant").(string)
	group := r.Context().Value("group").(string)
	usertype := r.Context().Value("usertype").(string)
	if usertype != "admin" && usertype != "superadmin" {
		result.Result = fmt.Sprintf("Only admins or superadmins can lock/unlock the rule")
		utils.WriteResult(w, result)
		return
	}
	err = db.DBLockHostRule(uuid, group, &data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type GetHostRuleResult struct {
	Result string `json:"Result"`
	db.HostRouteRule
}

// Get all host rules
func getAllHostRulesHandler(w http.ResponseWriter, r *http.Request) {
	uuid := r.Context().Value("tenant").(string)
	rules := db.DBFindAllHostRules(uuid)
	if rules == nil {
		rules = make([]db.HostRouteRule, 0)
	}
	utils.WriteResult(w, rules)

}

// Delete a host ID rule
func delHostRuleHandler(w http.ResponseWriter, r *http.Request) {
	var result RuleOpResult

	v := mux.Vars(r)
	hostid := v["host"]
	ruleid := v["rid"]
	uuid := r.Context().Value("tenant").(string)
	group := r.Context().Value("group").(string)
	err := db.DBDelHostRule(uuid, group, hostid, ruleid)
	if err != nil {
		result.Result = err.Error()
	} else {
		result = RuleOpResult{Result: "ok"}
	}
	utils.WriteResult(w, result)
}

// {"rid": "<value>", "rule":
//      [ ["lefttoken", "operator", "righttoken", "type", "isArray"],
//        ["lefttoken", "operator", "righttoken", "type", "isArray"],
//        [ ... ]
//      ]
// Rule ID is also the trace request ID (has to be unique)
// Add a new trace req rule
func addTraceReqRuleHandler(w http.ResponseWriter, r *http.Request) {
	var result RuleOpResult
	var data db.TraceReqRule

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		fmt.Println(err)
		result.Result = fmt.Sprintf("%v", err)
		utils.WriteResult(w, result)
		return
	}
	uuid := r.Context().Value("tenant").(string)
	err = db.DBAddTraceReqRule(uuid, &data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type GetTraceReqRuleResult struct {
	Result string `json:"Result"`
	db.TraceReqRule
}

// Get all trace req rules
func getAllTraceReqRulesHandler(w http.ResponseWriter, r *http.Request) {
	uuid := r.Context().Value("tenant").(string)
	rules := db.DBFindAllTraceReqRules(uuid)
	if rules == nil {
		rules = make([]db.TraceReqRule, 0)
	}
	utils.WriteResult(w, rules)

}

// Delete a trace req rule
func delTraceReqRuleHandler(w http.ResponseWriter, r *http.Request) {
	var result RuleOpResult

	v := mux.Vars(r)
	ruleid := v["rid"]
	uuid := r.Context().Value("tenant").(string)
	err := db.DBDelTraceReqRule(uuid, ruleid)
	if err != nil {
		result.Result = err.Error()
	} else {
		result = RuleOpResult{Result: "ok"}
	}
	utils.WriteResult(w, result)
}

// {"rid": "StatsRule", "rule":
//      [ ["lefttoken", "operator", "righttoken", "type", "isArray"]
//      ]
// Rule ID is constant
// Add a new stats rule
func addStatsRuleHandler(w http.ResponseWriter, r *http.Request) {
	var result RuleOpResult
	var data db.StatsRule

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		result.Result = "Read fail"
		utils.WriteResult(w, result)
		return
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		fmt.Println(err)
		result.Result = fmt.Sprintf("%v", err)
		utils.WriteResult(w, result)
		return
	}
	uuid := r.Context().Value("tenant").(string)
	err = db.DBAddStatsRule(uuid, &data)
	if err != nil {
		result.Result = err.Error()
		utils.WriteResult(w, result)
		return
	}

	result.Result = "ok"
	utils.WriteResult(w, result)
}

type GetStatsRuleResult struct {
	Result string `json:"Result"`
	db.StatsRule
}

// Get stats rule
func getAllStatsRulesHandler(w http.ResponseWriter, r *http.Request) {
	uuid := r.Context().Value("tenant").(string)
	rule := db.DBFindAllStatsRules(uuid)
	if rule == nil {
		rule = make([]db.StatsRule, 0)
	}
	utils.WriteResult(w, rule)

}

// Delete a stats rule
func delStatsRuleHandler(w http.ResponseWriter, r *http.Request) {
	var result RuleOpResult

	v := mux.Vars(r)
	ruleid := v["rid"]
	uuid := r.Context().Value("tenant").(string)
	err := db.DBDelStatsRule(uuid, ruleid)
	if err != nil {
		result.Result = err.Error()
	} else {
		result = RuleOpResult{Result: "ok"}
	}
	utils.WriteResult(w, result)
}
