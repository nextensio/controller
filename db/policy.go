package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var bungrpLock sync.RWMutex
var hostgrpLock sync.RWMutex
var trcgrpLock sync.RWMutex
var statgrpLock sync.RWMutex
var apolLock sync.Mutex
var rpolLock sync.Mutex
var tpolLock sync.Mutex
var spolLock sync.Mutex

// NOTE: The bson decoder will not work if the structure field names dont start with upper case
type Policy struct {
	PolicyId string `json:"pid" bson:"_id"`
	ChangeBy string `json:"changeby" bson:"changeby"`
	ChangeAt string `json:"changeat" bson:"changeat"`
	Majver   int    `json:"majver" bson:"majver"`
	Minver   int    `json:"minver" bson:"minver"`
	Rego     []rune `json:"rego" bson:"rego"`
}

func DBAddBasePolicies(uuid string, user string) error {
	accessPolicy := "package app.access\n\nallow = true\n"
	routePolicy := "package user.routing\n\ndefault route_tag = \"\"\n"
	tracePolicy := "package user.tracing\n\ndefault request = {\"no\": [\"\"]}\n"
	statsPolicy := "package user.stats\n\ndefault attributes = {\"exclude\": [\"uid\", \"maj_ver\", \"min_ver\", \"_hostname\", \"_model\", \"_osMinor\", \"_osPatch\", \"_osName\"]}\n"

	policy := Policy{PolicyId: "AccessPolicy", Rego: []rune(accessPolicy)}
	err := dbAddPolicy(uuid, user, &policy)
	if err != nil {
		return err
	}
	policy = Policy{PolicyId: "RoutePolicy", Rego: []rune(routePolicy)}
	err = dbAddPolicy(uuid, user, &policy)
	if err != nil {
		return err
	}
	policy = Policy{PolicyId: "TracePolicy", Rego: []rune(tracePolicy)}
	err = dbAddPolicy(uuid, user, &policy)
	if err != nil {
		return err
	}
	policy = Policy{PolicyId: "StatsPolicy", Rego: []rune(statsPolicy)}
	err = dbAddPolicy(uuid, user, &policy)
	if err != nil {
		return err
	}
	return nil
}

// This API will add a new policy or update a policy if it already exists
func DBAddPolicy(uuid string, admin string, data *Policy) error {

	t := DBFindTenant(uuid)
	if t == nil {
		return fmt.Errorf("Cannot find tenant %s", uuid)
	}
	if t.EasyMode {
		return fmt.Errorf("A policy cannot be added directly in Easy Mode")
	}
	return dbAddPolicy(uuid, admin, data)
}

func dbAddPolicy(uuid string, admin string, data *Policy) error {
	policy := DBFindPolicy(uuid, data.PolicyId)
	if policy != nil {
		minver := policy.Minver
		data.Minver = minver + 1
		data.Majver = policy.Majver
	} else {
		data.Majver = 1
		data.Minver = 0
	}

	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	policyCltn := dbGetCollection(uuid, "NxtPolicies")
	if policyCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	timenow := fmt.Sprintf("%s", time.Now().Format(time.RFC1123))
	err := policyCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.PolicyId},
		bson.D{
			{"$set", bson.M{"_id": data.PolicyId, "rego": data.Rego,
				"changeby": admin, "changeat": timenow,
				"majver": data.Majver, "minver": data.Minver}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindPolicy(tenant string, policyId string) *Policy {
	var policy Policy
	policyCltn := dbGetCollection(tenant, "NxtPolicies")
	if policyCltn == nil {
		return nil
	}
	err := policyCltn.FindOne(
		context.TODO(),
		bson.M{"_id": policyId},
	).Decode(&policy)
	if err != nil {
		return nil
	}
	return &policy
}

func DBFindAllPolicies(tenant string) []Policy {
	var policies []Policy

	policyCltn := dbGetCollection(tenant, "NxtPolicies")
	if policyCltn == nil {
		return nil
	}
	cursor, err := policyCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &policies)
	if err != nil {
		return nil
	}

	return policies
}

func DBDelPolicy(tenant string, policyId string) error {
	t := DBFindTenant(tenant)
	if t == nil {
		return fmt.Errorf("Cannot find tenant %s", tenant)
	}
	if t.EasyMode {
		return fmt.Errorf("A policy cannot be deleted directly in Easy Mode")
	}
	return dbDelPolicy(tenant, policyId)
}

func dbDelPolicy(tenant string, policyId string) error {
	policyCltn := dbGetCollection(tenant, "NxtPolicies")
	if policyCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	_, err := policyCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": policyId},
	)

	return err
}

// Check if given user attribute is included in any rules
func DBRulesContainAttribute(tenant string, attr string) bool {
	allbrules := DBFindBundleRules(tenant, "all", "all")
	for _, subrule := range allbrules {
		for i := 0; i < len(subrule.Rule); i++ {
			ltoken := getSnippetLeftToken(subrule.Rule[i])
			if ltoken == attr {
				return true
			}
		}
	}
	allhrules := DBFindHostRules(tenant, "all", "all")
	for _, subrule := range allhrules {
		for i := 0; i < len(subrule.Rule); i++ {
			ltoken := getSnippetLeftToken(subrule.Rule[i])
			if ltoken == attr {
				return true
			}
		}
	}
	alltrules := DBFindTraceReqRules(tenant, "all")
	for _, subrule := range alltrules {
		for i := 0; i < len(subrule.Rule); i++ {
			spl, ltoken := isSnippetLeftTokenSpecial(subrule.Rule[i])
			rtoken := getSnippetRightToken(subrule.Rule[i])
			// For trace requests, user attribute can be in a match
			// expression or in the attribute list, so check both.
			if !spl {
				if ltoken == attr {
					return true
				}
			} else {
				if ltoken == "attrlist" {
					// Need to look for attribute in rtoken
					rtoken = strings.ReplaceAll(rtoken, ",", " ")
					rtokenarray := strings.Split(rtoken, " ")
					for _, rtok := range rtokenarray {
						if rtok == attr {
							return true
						}
					}
				}
			}
		}
	}
	allsrules := DBFindStatsRule(tenant)
	for _, subrule := range allsrules {
		for i := 0; i < len(subrule.Rule); i++ {
			spl, ltoken := isSnippetLeftTokenSpecial(subrule.Rule[i])
			rtoken := getSnippetRightToken(subrule.Rule[i])
			// For stats, user attribute can only be in attribute list
			if spl {
				if ltoken == "attrlist" {
					// Need to look for attribute in rtoken
					rtoken = strings.ReplaceAll(rtoken, ",", " ")
					rtokenarray := strings.Split(rtoken, " ")
					for _, rtok := range rtokenarray {
						if rtok == attr {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// Validate that the rule snippets contain only attributes owned by the
// specified group.
// The filter is a temporary hack to filter out snippets for attributes
// not owned by the group. This hack is needed because the ux code sends
// all snippets during an add/update instead of sending the snippets just
// for the group involved. So this is only for backward compatibility
// until the controller UI is changed.
// Rule snippets pushed during an add or update should be only for the
// specified group instead of all snippets in the rule.
func dbValidateGroupOwnership(tenant string, rule *[][]string, group string, poltype string, filter bool) (bool, [][]string) {
	var filtSnip [][]string
	var dupSnip map[string][]string

	// Get all user attributes from AttrSet
	// For each snippet in rule, check if user attribute ownership as
	// per AttrSet matches group.
	noattrs := true
	usrattrs := DBFindSpecificAttrSet(tenant, "Users", group)
	if usrattrs != nil {
		// We have user attributes defined for the group, so turn flag off
		noattrs = false
	}
	dupSnip = make(map[string][]string, 0)
	for _, snip := range *rule {
		// A snippet is of this form :
		// [lefttoken, operator, righttoken, type, isArray] where
		// type == "string", "boolean", "number"
		// isArray == "true" or "false"
		// operator values can be ==, !=, >, <, >=, <= depending on type
		// lefttoken is a user attribute name or a special token
		// if lefttoken is a user attribute name, righttoken has the values
		// if lefttoken is a special token, righttoken may be a route tag
		// or a list of user attribute names, depending on lefttoken.
		//
		// First check if snippet lefttoken is special - "attrlist" (trace
		// and stats rules), "tag" (route rule) or "uid" (all except stats).
		// If route tag, preserve snippet and do nothing else.
		// If "attrlist", ensure that attributes in the righttoken are all
		// for the specifid group as per AttrSet.
		// In all other cases, lefttoken should be "uid" or the name of a
		// user attribute. If user attribute name, ensure that it is owned
		// by specified group as per AttrSet.
		spl, ltoken := isSnippetLeftTokenSpecial(snip)
		glog.Infof("ValidateGroupRule: Found left token " + ltoken)
		if spl {
			// We have a special snippet where lefttoken is either one
			// of these: "uid", "tag", or "attrlist".
			// Access policy rule can have one uid snippet only
			// Route policy rule can have one uid snippet and must have one tag snippet
			// Trace policy rule can have one uid snippet and multiple attrlist snippets
			// Stats policy rule can have one or more attrlist snippets only
			switch ltoken {
			case "uid":
				if poltype == "Stats" {
					return false, filtSnip
				}
			case "tag":
				if poltype != "Route" {
					return false, filtSnip
				}
			case "attrlist":
				if poltype == "Access" || poltype == "Route" {
					return false, filtSnip
				}
				// Need to validate attrlist in rtoken for ownership by group
				rtoken := getSnippetRightToken(snip)
				rtoken = strings.ReplaceAll(rtoken, ",", " ")
				rtoken = strings.Trim(rtoken, " ")
				rtokenarray := strings.Split(rtoken, " ")
				for _, attr := range rtokenarray {
					attr = strings.Trim(attr, " ")
					if attr != "" {
						f := false
						for _, ua := range usrattrs {
							if (ua.Name == attr) && (ua.Group == group) {
								f = true
								break
							}
						}
						if !f {
							glog.Infof("ValidateGroupRule: attribute list has attribute not owned by " + group)
							return false, filtSnip
						}
					}
				}
			default:
				// Unknown special token; bail out
				glog.Errorf("ValidateGroupRule: Unknown token in rule snippet - ", ltoken)
				return false, filtSnip
			}
			// Since the snippets for route tag, user ids, and attribute lists
			// currently have no group ownership, we need to ensure they are not
			// duplicated when different groups add their snippets (esp since the
			// ux code sends all snippets everytime).
			// This piece of code uses a map structure to keep track of the special
			// tokens seen together with their values in the righttokens.
			// If the same lefttoken is seen again with the same value in righttoken,
			// we ignore it.
			rtok := getSnippetRightToken(snip)
			val, found := dupSnip[ltoken]
			if found {
				dup := false
				for _, valpart := range val {
					if valpart == rtok {
						// Duplicate, skip
						dup = true
						break
					}
				}
				if dup {
					continue
				}
			}
			dupSnip[ltoken] = append(dupSnip[ltoken], rtok)
			filtSnip = append(filtSnip, snip)
			glog.Infof("ValidateGroupRule: Added snippet for " + ltoken)
			continue
		} else {
			// Snippet is for a user attribute, not a special token
			if noattrs {
				// If there are no user attributes defined, return false, since
				// there cannot be a snippet for a user attribute. We have already
				// covered the special cases above.
				glog.Errorf("ValidateGroupRule: rule contains undefined attributes")
				return false, filtSnip
			}
		}
		// We reach here if lefttoken is a user attribute name.
		// Search in our AttrSet and if found, ensure the attribute belongs
		// to the specified group. If not found, return false
		found := false
		for _, attr := range usrattrs {
			if attr.Name == ltoken {
				if attr.Group != group {
					// Attribute found but group does not match
					if !filter {
						glog.Errorf("ValidateGroupRule: rule contains attribute for different group")
						return false, filtSnip
					}
					break
				}
				// Attribute found and group matches
				found = true
				filtSnip = append(filtSnip, snip)
				break
			}
		}
		if !found {
			// Unknown attribute
			if !filter {
				glog.Errorf("ValidateGroupRule: rule contains unknown attribute")
				return false, filtSnip
			}
		}
	}
	glog.Infof("ValidateGroupRule: found %d snippets in rule", len(filtSnip))
	return true, filtSnip
}

//----------------------------------Bundle ID rules-----------------------------------
// Access Policy is generated from the rules for one or more bundle ids

// A rule is configured for a bundle. The rule can be composed of
// sub-rules for one or more groups. Each sub-rule is a collection
// of one or more match expressions (called snippets).
// The key is composed of Bid, Rid and Group fields concatenated
// together with ":".
// Version tracks the version of each sub-rule and is used to ensure
// that if multiple admins try to update the same sub-rule, one admin
// does not overwrite the updates of another.
type BundleAccessRule struct {
	Bid     string     `json:"bid" bson:"bid"`
	Rid     string     `json:"rid" bson:"rid"`
	Group   string     `json:"group" bson:"group"`
	Version int        `json:"version" bson:"version"`
	Admin   string     `json:"admin" bson:"admin"`
	Rule    [][]string `json:"rule" bson:"rule"`
}

// This API will add new match expressions (snippets) for a group to a bundle rule,
// overriding any previous snippets of the group if they exist.
// For the update case, the Version value provided should match what's in the DB to
// ensure two admins for a group don't stomp on each other.
func DBAddBundleRuleGroup(uuid string, group string, admin string, body *[]byte) error {
	var data BundleAccessRule

	// First validate. Ensure tenant is valid. Next ensure tenant is in Easy Mode.
	// Then ensure match expressions are all based on the attributes owned by the
	// group.
	t := DBFindTenant(uuid)
	if t == nil {
		return fmt.Errorf("Cant find tenant %s", uuid)
	}
	if !t.EasyMode {
		return fmt.Errorf("Rules are supported only in Easy Mode")
	}
	err := json.Unmarshal(*body, &data)
	if err != nil {
		return fmt.Errorf("Rule unmarshal error - %v", err)
	}
	sts, newsnips := dbValidateGroupOwnership(uuid, &data.Rule, group, "Access", true)
	if !sts {
		return fmt.Errorf("Bundle rule group has attributes not belonging to group")
	}
	bundleRuleCltn := dbGetCollection(uuid, "NxtBundleRules")
	if bundleRuleCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	if data.Group == "" {
		data.Group = group
	}
	data.Admin = admin
	// Set the key
	Id := data.Bid + ":" + data.Rid + ":" + data.Group

	// Lock anyone else from doing this add/update simultaneously
	bungrpLock.Lock()
	defer bungrpLock.Unlock()
	// Also ensure the access policy is not generated simultaneously.
	// We don't want the rules changing while the policy is being
	// generated
	apolLock.Lock()
	defer apolLock.Unlock()
	// Now read and add/update
	bunrul := dbFindBundleRuleGroup(bundleRuleCltn, Id)
	if bunrul == nil {
		data.Version = 0
		//} else if bunrul.Version != data.Version {
		// Update case. Cannot update if version has changed
		//return fmt.Errorf("Bundle rule has changed in DB. Refresh rule and try again")
	} else {
		data.Version = bunrul.Version + 1
	}
	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	aerr := bundleRuleCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": Id},
		bson.D{
			{"$set", bson.M{"rule": newsnips, "rid": data.Rid, "bid": data.Bid,
				"group": data.Group, "admin": data.Admin, "version": data.Version}},
		},
		&opt,
	)

	if aerr != nil {
		return aerr.Err()
	}
	return nil
}

// Gets a group of match expressions within a specific rule for a bundle
func dbFindBundleRuleGroup(cltn *mongo.Collection, Id string) *BundleAccessRule {
	var rule BundleAccessRule

	err := cltn.FindOne(
		context.TODO(),
		bson.M{"_id": Id},
	).Decode(&rule)
	if err != nil {
		return nil
	}
	return &rule
}

// This function can get
// 1. a specific rule for a specific bundle - specify both bid and rid
// 2. all rules for a specific bundle - specify just bid
// 3. all rules for all bundles - specify just bid = "all"
func DBFindBundleRules(tenant string, bid string, rid string) []BundleAccessRule {
	var rules []BundleAccessRule
	var err error
	var cursor *mongo.Cursor

	t := DBFindTenant(tenant)
	if t == nil {
		return nil
	}
	if !t.EasyMode {
		return nil
	}
	bundleRuleCltn := dbGetCollection(tenant, "NxtBundleRules")
	if bundleRuleCltn == nil {
		return nil
	}
	if bid == "all" {
		cursor, err = bundleRuleCltn.Find(context.TODO(), bson.M{})
	} else {
		if rid == "" {
			cursor, err = bundleRuleCltn.Find(context.TODO(), bson.M{"bid": bid})
		} else {
			cursor, err = bundleRuleCltn.Find(context.TODO(), bson.M{"bid": bid, "rid": rid})
		}
	}
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &rules)
	if err != nil {
		return nil
	}

	return rules
}

// Deletes a specific group of match expressions within a bundle rule
func DBDelBundleRuleGroup(tenant string, bid string, ruleid string, group string) error {
	t := DBFindTenant(tenant)
	if t == nil {
		return fmt.Errorf("Unknown tenant " + tenant)
	}
	if !t.EasyMode {
		return fmt.Errorf("Rules supported only in Easy Mode")
	}
	bundleRuleCltn := dbGetCollection(tenant, "NxtBundleRules")
	if bundleRuleCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	id := bid + ":" + ruleid + ":" + group
	bungrpLock.Lock()
	defer bungrpLock.Unlock()
	_, err := bundleRuleCltn.DeleteOne(context.TODO(), bson.M{"_id": id})
	return err
}

//----------------------------------Host ID rules-----------------------------------
// Route Policy is generated from the rules for one or more host ids.
// Note that Route policy also supports host access control

// A rule is configured for a bundle. The rule can be composed of
// sub-rules for one or more groups. Each sub-rule is a collection
// of one or more match expressions (called snippets).
// The key is composed of Host, Rid and Group fields concatenated
// together with ":".
// Version tracks the version of each sub-rule and is used to ensure
// that if multiple admins try to update the same sub-rule, one admin
// does not overwrite the updates of another.
type HostRouteRule struct {
	Host    string     `json:"host" bson:"host"`
	Rid     string     `json:"rid" bson:"rid"`
	Group   string     `json:"group" bson:"group"`
	Version int        `json:"version" bson:"version"`
	Admin   string     `json:"admin" bson:"admin"`
	Rule    [][]string `json:"rule" bson:"rule"`
}

// This API will add new match expressions (snippets) for a group to a host route rule,
// overriding any previous snippets of the group if they exist.
// For the update case, the Version value provided should match what's in the DB to
// ensure two admins for a group don't stomp on each other.
func DBAddHostRuleGroup(uuid string, group string, admin string, body *[]byte) error {
	var data HostRouteRule

	// First validate. Ensure tenant is valid. Next ensure tenant is in Easy Mode.
	// Then ensure match expressions are all based on the attributes owned by the
	// group.
	t := DBFindTenant(uuid)
	if t == nil {
		return fmt.Errorf("Cant find tenant %s", uuid)
	}
	if !t.EasyMode {
		return fmt.Errorf("Rules are supported only in Easy Mode")
	}
	err := json.Unmarshal(*body, &data)
	if err != nil {
		return fmt.Errorf("Rule unmarshal error - %v", err)
	}
	sts, newsnips := dbValidateGroupOwnership(uuid, &data.Rule, group, "Route", true)
	if !sts {
		return fmt.Errorf("Host route rule group has attributes not belonging to group")
	}
	hostRuleCltn := dbGetCollection(uuid, "NxtHostRules")
	if hostRuleCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	if data.Group == "" {
		data.Group = group
	}
	data.Admin = admin
	// Set the key
	Id := data.Host + ":" + data.Rid + ":" + data.Group

	// Lock anyone else from doing this add/update simultaneously
	hostgrpLock.Lock()
	defer hostgrpLock.Unlock()
	// Also ensure the route policy is not generated simultaneously.
	// We don't want the rules changing while the policy is being
	// generated
	rpolLock.Lock()
	defer rpolLock.Unlock()
	// Now read and add/update
	hostrul := dbFindHostRuleGroup(hostRuleCltn, Id)
	if hostrul == nil {
		data.Version = 0
		//} else if hostrul.Version != data.Version {
		// Update case. Cannot update if version has changed
		//return fmt.Errorf("Host rule has changed in DB. Refresh rule and try again")
	} else {
		data.Version = hostrul.Version + 1
	}
	// The upsert option asks the DB to add a host sub-rule if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	aerr := hostRuleCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": Id},
		bson.D{
			{"$set", bson.M{"rule": newsnips, "rid": data.Rid, "host": data.Host,
				"group": data.Group, "admin": data.Admin, "version": data.Version}},
		},
		&opt,
	)

	if aerr != nil {
		return aerr.Err()
	}
	return nil
}

func DBHostRuleExists(tenant string, host string, tags *[]string) bool {
	var rule HostRouteRule

	hostRuleCltn := dbGetCollection(tenant, "NxtHostRules")
	if hostRuleCltn == nil {
		return false
	}
	cursor, err := hostRuleCltn.Find(
		context.TODO(),
		bson.M{"host": host},
	)
	if err != nil {
		return false
	}

	defer cursor.Close(context.TODO())
	for cursor.Next(context.TODO()) {
		// tag == nil means return true as long as any one rule exists
		if tags == nil {
			return true
		}
		if err = cursor.Decode(&rule); err != nil {
			return false
		}

		for _, t := range *tags {
			for _, r := range rule.Rule {
				if len(r) >= 3 && r[0] == "tag" && r[2] == t {
					return true
				}
			}
		}
	}

	return false
}

// Gets a group of match expressions within a specific rule for a host
func dbFindHostRuleGroup(cltn *mongo.Collection, Id string) *HostRouteRule {
	var rule HostRouteRule

	err := cltn.FindOne(context.TODO(), bson.M{"_id": Id}).Decode(&rule)
	if err != nil {
		return nil
	}
	return &rule
}

// This function can get
// 1. a specific rule for a specific host - specify both host and rid
// 2. all rules for a specific host - specify just host
// 3. all rules for all hosts - specify just host = "all"
func DBFindHostRules(tenant string, host string, rid string) []HostRouteRule {
	var rules []HostRouteRule
	var err error
	var cursor *mongo.Cursor

	t := DBFindTenant(tenant)
	if t == nil {
		return nil
	}
	if !t.EasyMode {
		return nil
	}
	hostRuleCltn := dbGetCollection(tenant, "NxtHostRules")
	if hostRuleCltn == nil {
		return nil
	}
	if host == "all" {
		cursor, err = hostRuleCltn.Find(context.TODO(), bson.M{})
	} else {
		if rid == "" {
			cursor, err = hostRuleCltn.Find(context.TODO(), bson.M{"host": host})
		} else {
			cursor, err = hostRuleCltn.Find(context.TODO(), bson.M{"host": host, "rid": rid})
		}
	}
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &rules)
	if err != nil {
		return nil
	}
	return rules
}

// Deletes a specific group of match expressions within a host rule
func DBDelHostRuleGroup(tenant string, hostid string, ruleid string, group string) error {
	t := DBFindTenant(tenant)
	if t == nil {
		return fmt.Errorf("Unknown tenant " + tenant)
	}
	if !t.EasyMode {
		return fmt.Errorf("Rules supported only in Easy Mode")
	}
	hostRuleCltn := dbGetCollection(tenant, "NxtHostRules")
	if hostRuleCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	id := hostid + ":" + ruleid + ":" + group
	hostgrpLock.Lock()
	defer hostgrpLock.Unlock()
	_, err := hostRuleCltn.DeleteOne(context.TODO(), bson.M{"_id": id})
	return err
}

//----------------------------------TraceRequest rules-----------------------------------
// Trace Policy is generated from the rules for one or more trace requests

// A rule is configured for a trace req. The rule can be composed of
// sub-rules for one or more groups. Each sub-rule is a collection
// of one or more match expressions (called snippets).
// The key is composed of Rid and Group fields concatenated
// together with ":".
// Version tracks the version of each sub-rule and is used to ensure
// that if multiple admins try to update the same sub-rule, one admin
// does not overwrite the updates of another.
type TraceReqRule struct {
	Rid     string     `json:"rid" bson:"rid"`
	Group   string     `json:"group" bson:"group"`
	Version int        `json:"version" bson:"version"`
	Admin   string     `json:"admin" bson:"admin"`
	Rule    [][]string `json:"rule" bson:"rule"`
}

// This API will add new match expressions (snippets) for a group to a trace req rule,
// overriding any previous snippets of the group if they exist.
// For the update case, the Version value provided should match what's in the DB to
// ensure two admins for a group don't stomp on each other.
func DBAddTraceReqRuleGroup(uuid string, group string, admin string, body *[]byte) error {
	var data TraceReqRule

	// First validate. Ensure tenant is valid. Next ensure tenant is in Easy Mode.
	// Then ensure match expressions are all based on the attributes owned by the
	// group.
	t := DBFindTenant(uuid)
	if t == nil {
		return fmt.Errorf("Cant find tenant %s", uuid)
	}
	if !t.EasyMode {
		return fmt.Errorf("Rules are supported only in Easy Mode")
	}
	err := json.Unmarshal(*body, &data)
	if err != nil {
		return fmt.Errorf("Rule unmarshal error - %v", err)
	}
	sts, newsnips := dbValidateGroupOwnership(uuid, &data.Rule, group, "Trace", true)
	if !sts {
		return fmt.Errorf("Trace req rule group has attributes not belonging to group")
	}
	traceReqRuleCltn := dbGetCollection(uuid, "NxtTraceReqRules")
	if traceReqRuleCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	if data.Group == "" {
		data.Group = group
	}
	data.Admin = admin
	// Set the key
	Id := data.Rid + ":" + data.Group

	// Lock anyone else from doing this add/update simultaneously
	trcgrpLock.Lock()
	defer trcgrpLock.Unlock()
	// Also ensure the trace req policy is not generated simultaneously.
	// We don't want the rules changing while the policy is being
	// generated
	tpolLock.Lock()
	defer tpolLock.Unlock()
	// Now read and add/update
	trcrul := dbFindTraceReqRuleGroup(traceReqRuleCltn, Id)
	if trcrul == nil {
		data.Version = 0
		//} else if trcrul.Version != data.Version {
		// Update case. Cannot update if version has changed
		//return fmt.Errorf("Trace req rule has changed in DB. Refresh rule and try again")
	} else {
		data.Version = trcrul.Version + 1
	}
	// The upsert option asks the DB to add a trace req sub-rule if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	aerr := traceReqRuleCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": Id},
		bson.D{
			{"$set", bson.M{"rule": newsnips, "rid": data.Rid,
				"group": data.Group, "admin": data.Admin, "version": data.Version}},
		},
		&opt,
	)

	if aerr != nil {
		return aerr.Err()
	}
	return nil
}

// Gets a group of match expressions within a specific rule for a trace req
func dbFindTraceReqRuleGroup(cltn *mongo.Collection, Id string) *TraceReqRule {
	var rule TraceReqRule

	err := cltn.FindOne(
		context.TODO(),
		bson.M{"_id": Id},
	).Decode(&rule)
	if err != nil {
		return nil
	}
	return &rule
}

// This function gets
// 1. the rule for a specific trace req  - specify trace req id
// 2. rules for all trace reqs - specify trace req id = "all"
func DBFindTraceReqRules(tenant string, treq string) []TraceReqRule {
	var rules []TraceReqRule
	var err error
	var cursor *mongo.Cursor

	t := DBFindTenant(tenant)
	if t == nil {
		return nil
	}
	if !t.EasyMode {
		return nil
	}

	traceReqRuleCltn := dbGetCollection(tenant, "NxtTraceReqRules")
	if traceReqRuleCltn == nil {
		return nil
	}
	if treq == "all" {
		cursor, err = traceReqRuleCltn.Find(context.TODO(), bson.M{})
	} else {
		cursor, err = traceReqRuleCltn.Find(context.TODO(), bson.M{"rid": treq})
	}
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &rules)
	if err != nil {
		return nil
	}
	return rules
}

// Deletes a specific group of match expressions within a trace req rule
func DBDelTraceReqRuleGroup(tenant string, ruleid string, group string) error {
	t := DBFindTenant(tenant)
	if t == nil {
		return fmt.Errorf("Unknown tenant " + tenant)
	}
	if !t.EasyMode {
		return fmt.Errorf("Rules supported only in Easy Mode")
	}
	traceReqRuleCltn := dbGetCollection(tenant, "NxtTraceReqRules")
	if traceReqRuleCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	id := ruleid + ":" + group
	trcgrpLock.Lock()
	defer trcgrpLock.Unlock()
	_, err := traceReqRuleCltn.DeleteOne(context.TODO(), bson.M{"_id": id})
	return err
}

//----------------------------------Stats rule-----------------------------------
// Stats Policy is generated from a single rule called "StatsRule" that specifies the
// user attributes to be used as dimensions for the stats

type StatsRule struct {
	Rid     string     `json:"rid" bson:"_id"`
	Group   string     `json:"group" bson:"group"`
	Version int        `json:"version" bson:"version"`
	Admin   string     `json:"admin" bson:"admin"`
	Rule    [][]string `json:"rule" bson:"rule"`
}

// This API will add a new stats rule or update stats rule if it already exists
func DBAddStatsRuleGroup(uuid string, group string, admin string, body *[]byte) error {
	var data StatsRule

	// First validate. Ensure tenant is valid. Next ensure tenant is in Easy Mode.
	// Then ensure match expressions are all based on the attributes owned by the
	// group.
	t := DBFindTenant(uuid)
	if t == nil {
		return fmt.Errorf("Cant find tenant %s", uuid)
	}
	if !t.EasyMode {
		return fmt.Errorf("Rules are supported only in Easy Mode")
	}
	err := json.Unmarshal(*body, &data)
	if err != nil {
		return fmt.Errorf("Rule unmarshal error - %v", err)
	}
	sts, newsnips := dbValidateGroupOwnership(uuid, &data.Rule, group, "Stats", true)
	if !sts {
		return fmt.Errorf("Bundle rule group has attributes not belonging to group")
	}

	statsRuleCltn := dbGetCollection(uuid, "NxtStatsRule")
	if statsRuleCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	if data.Group == "" {
		data.Group = group
	}
	data.Admin = admin
	data.Rid = "StatsRule"
	// Set the key
	Id := data.Rid + ":" + data.Group

	// Lock anyone else from doing this add/update simultaneously
	statgrpLock.Lock()
	defer statgrpLock.Unlock()
	// Also ensure the stats policy is not generated simultaneously.
	// We don't want the rules changing while the policy is being
	// generated
	spolLock.Lock()
	defer spolLock.Unlock()
	// Now read and add/update
	statrul := dbFindStatsRuleGroup(statsRuleCltn, Id)
	if statrul == nil {
		data.Version = 0
		//} else if statrul.Version != data.Version {
		// Update case. Cannot update if version has changed
		//return fmt.Errorf("Stats rule has changed in DB. Refresh rule and try again")
	} else {
		data.Version = statrul.Version + 1
	}
	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	aerr := statsRuleCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": Id},
		bson.D{
			{"$set", bson.M{"rule": newsnips, "rid": data.Rid,
				"group": data.Group, "admin": data.Admin, "version": data.Version}},
		},
		&opt,
	)

	if aerr != nil {
		return aerr.Err()
	}
	return nil
}

// Gets a group of match expressions within a specific rule for a bundle
func dbFindStatsRuleGroup(cltn *mongo.Collection, Id string) *StatsRule {
	var rule StatsRule

	err := cltn.FindOne(
		context.TODO(),
		bson.M{"_id": Id},
	).Decode(&rule)
	if err != nil {
		return nil
	}
	return &rule
}

// This function gets the stats rule (there is only one).
func DBFindStatsRule(tenant string) []StatsRule {
	var rules []StatsRule

	statsRuleCltn := dbGetCollection(tenant, "NxtStatsRule")
	if statsRuleCltn == nil {
		return nil
	}
	cursor, err := statsRuleCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &rules)
	if err != nil {
		return nil
	}

	return rules
}

// Deletes a specific snippet for attributes selected by a group in the
// stats rule.
func DBDelStatsRuleGroup(tenant string, group string) error {
	t := DBFindTenant(tenant)
	if t == nil {
		return fmt.Errorf("Unknown tenant " + tenant)
	}
	if !t.EasyMode {
		return fmt.Errorf("Rules supported only in Easy Mode")
	}
	statsRuleCltn := dbGetCollection(tenant, "NxtStatsRule")
	if statsRuleCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	id := "StatsRule:" + group
	statgrpLock.Lock()
	defer statgrpLock.Unlock()
	_, err := statsRuleCltn.DeleteOne(context.TODO(), bson.M{"_id": id})
	return err
}

//----------------------------Rules to policy conversion------------------------

// **This code is only applicable in Easy Mode**

func DBGeneratePolicyFromRules(tenant string, policyid string, admin string) error {
	// First ensure tenant is valid and in Easy Mode.
	t := DBFindTenant(tenant)
	if t == nil {
		return fmt.Errorf("Generate policy from rules - unknown tenant " + tenant)
	}
	if !t.EasyMode {
		return fmt.Errorf("Generate policy from rules - supported only in Easy Mode")
	}

	// When we generate a policy from the rules, need to ensure that
	// 1. the rules are not changed in parallel. So need to block any
	//    update/deletion of the rules until the policy is generated.
	// 2. if an update/deletion of any rules is already in progress, need
	//    to hold off on the policy generation until the updation/deletion
	//    is complete.
	// 3. two or more admins are not trying to generate the same policy
	//    in parallel. We don't want the output policy to get munged. So
	//    allow only one user to generate the same policy at a time.
	var res []string
	switch policyid {
	case "AccessPolicy":
		apolLock.Lock()
		defer apolLock.Unlock()
		res = dbGeneratePolicyFromBundleRules(tenant)
	case "RoutePolicy":
		rpolLock.Lock()
		defer rpolLock.Unlock()
		res = dbGeneratePolicyFromHostRules(tenant)
	case "TracePolicy":
		tpolLock.Lock()
		defer tpolLock.Unlock()
		res = dbGeneratePolicyFromTraceReqRules(tenant)
	case "StatsPolicy":
		spolLock.Lock()
		defer spolLock.Unlock()
		res = dbGeneratePolicyFromStatsRule(tenant)
	default:
		return fmt.Errorf("Generate policy from rules - unknown/unsupported policy " + policyid)
	}
	// The result of the policy generation is returned in a string array.
	// The first element indicates if operation was "ok" or had an error.
	// If "ok", the second element contains the generated policy.
	if res[0] != "ok" {
		return fmt.Errorf(res[0])
	}
	policy := Policy{
		PolicyId: policyid,
	}
	policy.Rego = []rune(res[1])
	return dbAddPolicy(tenant, admin, &policy)
}

// ------------------Access Policy generation functions-------------------------

func dbGeneratePolicyFromBundleRules(tenant string) []string {
	// Access policy generation
	// bundleRuleData contains data in this format :
	//  [bid1, ruleid1, grp1, rule:[[snippet1], [snippet2], [snippet3], ..]]
	//  [bid1, ruleid2, grp1, rule:[[snippet1], [snippet2], ..]]
	//  [bid2, ruleid1, grp2, rule:[[snippet1], [snippet2], ..]]
	//  [bid3, ruleid1, grp3, rule:[[snippet1], [snippet2], [snippet3], ..]]
	//  [bid3, ruleid2, grp2, rule:[[snippet1], ..]]
	//    and so on ...
	//  A snippet is of this form :
	//  [userattr, operator, const, type, isArray] where
	//  type == "string", "boolean", "number"
	//  isArray == "true" or "false"
	//  operator values are ==, !=, >, <, >=, <=

	// Read bundle rules collection for all rules of all bundles.
	// Find unique bids and rule ids.
	// Accumulate snippets for each bundle rule and then process
	// each bundle rule.
	var bidMap map[string][]string   // key = bid
	var ridMap map[string][][]string // key = bid:rid

	bidMap = make(map[string][]string, 0)
	ridMap = make(map[string][][]string, 0)
	verInfo := ""

	RetVal := make([]string, 2)
	RegoPolicy := generateAccessPolicyHeader()
	allRules := DBFindBundleRules(tenant, "all", "")
	// We have all rules for all bundles
	for _, subrule := range allRules {
		// A subrule is a collection of snippets (match expressions)
		// for a group within a rule for a bundle
		// First check if we've seen this bundle
		rids, found1 := bidMap[subrule.Bid]
		if found1 {
			// Known bundle id. rids contains rule ids known so far
			// for this bundle. Check if the rule id is new or
			// known.
			found2 := false
			for _, rid := range rids {
				if rid == subrule.Rid {
					found2 = true
					break
				}
			}
			if !found2 {
				// new rule id found for bid
				bidMap[subrule.Bid] = append(bidMap[subrule.Bid], subrule.Rid)
			}
		} else {
			// New bundle id, so track bundle and rule ids.
			bidMap[subrule.Bid] = append(bidMap[subrule.Bid], subrule.Rid)
		}
		// Consolidate all the snippets from the group into the rule
		bid := subrule.Bid
		rid := subrule.Rid
		for i := 0; i < len(subrule.Rule); i++ {
			ridMap[bid+":"+rid] = append(ridMap[bid+":"+rid], subrule.Rule[i])
		}
		grp := subrule.Group
		ver := fmt.Sprintf("%d", subrule.Version)
		verInfo = verInfo + "# Rule: " + rid + ", Group: " + grp + ", Version: " + ver + "\n"
	}
	RegoPolicy += verInfo + "\n"

	// Now we have maps of unique bid and rid values
	// Loop through the maps to accumulate all snippets for a bundle
	// rule and then process the rule.
	for bid, rids := range bidMap {
		// For each rule for a given bundle
		for _, rid := range rids {
			var bundleRuleData [][]string
			bundleRuleData = ridMap[bid+":"+rid]
			if len(bundleRuleData) < 1 {
				// This rule is empty ! Skip
				continue
			}
			Rule, errstr := processBundleRule(bid, bundleRuleData)
			if errstr == "" {
				// No error. Accumulate the Rego code for the rule.
				RegoPolicy = RegoPolicy + Rule
			} else {
				RetVal[0] = errstr
				RetVal[1] = ""
				return RetVal
			}
		}
	}
	RetVal[0] = "ok"
	RetVal[1] = RegoPolicy
	return RetVal
}

func generateAccessPolicyHeader() string {
	return "package app.access\nallow = is_allowed\ndefault is_allowed = false\n\n"
}

func processBundleRule(bid string, bundleRule [][]string) (string, string) {
	Exprs := ""
	RuleStart := "is_allowed {\n"
	BidConst := "    input.bid == \"" + bid + "\"\n"
	for _, snippet := range bundleRule {
		// snippet is an array of strings
		spl, ltoken := isSnippetLeftTokenSpecial(snippet)
		// Special token can only be "uid"
		if spl && (ltoken != "uid") {
			return "", "Invalid snippet in Access Policy rule"
		}
		optoken := getSnippetOpToken(snippet)
		uatype := strings.ToLower(getSnippetLeftTokenType(snippet))
		rtoken := getSnippetRightToken(snippet)
		rtokenarray := []string{""}

		// Do some pre-processing on rtoken to figure out more details.
		// rtoken is always a constant. Could be single value or array
		// of values.
		// Single value can have wild card if string type. Support only '*'
		// for now, with delimiter as '.'.
		// Multiple values can be entered as [x y z] or [x,y,z] or [x, y, z]
		// For string values, add double quotes if missing.
		// Always trim all values.
		// For processing array of values, first replace any comma with a
		// space, then split based on space. Remove any null strings to
		// compress array.
		// To search for anything other than a word or whitespace, use
		// 'const regex = /[^\w\s]/g' if using regexp matching (future).

		haswildcard := false
		issingle := true
		lts := "[_]"
		if !isSnippetLeftTokenMultiValue(snippet) {
			lts = ""
		}
		rts := "array[_]"

		if uatype == "string" {
			// User attribute is string type. rtoken must be a string or
			// string array. Or else, right token contains user ids.
			if strings.Contains(rtoken, ",") {
				rtoken = strings.ReplaceAll(rtoken, ",", " ")
			}
			rtoken = strings.Trim(rtoken, " ")
			if strings.Contains(rtoken, " ") {
				// Seems to be case of multiple string values
				issingle = false
				rtokenarray = rightTokenArray(rtoken, "string")
			}
			if issingle {
				haswildcard = checkWildCard(rtoken)
				if !strings.HasPrefix(rtoken, "\"") {
					rtoken = "\"" + rtoken
				}
				if !strings.HasSuffix(rtoken, "\"") {
					rtoken += "\""
				}
			}
		} else {
			// right token contains user attribute value(s) which are not
			// string type
			if strings.Contains(rtoken, ",") {
				rtoken = strings.ReplaceAll(rtoken, ",", " ")
			}
			rtoken = strings.Trim(rtoken, " ")
			if strings.Contains(rtoken, " ") {
				// Seems to be case of multiple non-string values
				issingle = false
				rtokenarray = rightTokenArray(rtoken, uatype)
			}
		}

		if issingle {
			rts = ""
		}
		if ltoken == "uid" {
			// ltoken is user id
			if !issingle {
				// We have an array of values to match this attribute.
				Exprs += processArray("uid", rtokenarray, optoken, "")
			} else {
				// We have a single value to match
				if haswildcard {
					// glob.match("*foo.com", [], input.user.uid)
					Exprs += processWildCard("uid", rtoken, optoken, "")
				} else {
					// input.user.uid <op> "value"
					Exprs += "    input.user.uid " + optoken + " " + rtoken + "\n"
				}
			}
		} else {
			// ltoken is a user attribute
			// It could be matched with a single value, or with multiple
			// values. If single value, it could have a wildcard.
			if !issingle {
				// We have an array of values to match this attribute
				Exprs += processArray(ltoken, rtokenarray, optoken, lts)
			} else {
				// We have a single value to match
				if haswildcard && (uatype == "string") {
					Exprs += processWildCard(ltoken, rtoken, optoken, lts)
				} else {
					Exprs += "    input.user." + ltoken + lts
					Exprs += " " + optoken + " " + rtoken + rts + "\n"
				}
			}
		}
	}
	RuleEnd := "}\n\n"
	Rule := RuleStart + BidConst + Exprs + RuleEnd
	return Rule, ""
}

// --------------------Route Policy generation functions-------------------------

func dbGeneratePolicyFromHostRules(tenant string) []string {
	// Route policy generation
	// hostRuleData contains data in this format :
	//  [host1, ruleid1, grp1, rule:[[snippet1], [snippet2], [snippet3], ..]]
	//  [host1, ruleid2, grp1, rule:[[snippet1], [snippet2], ..]]
	//  [host2, ruleid1, grp2, rule:[[snippet1], [snippet2], ..]]
	//  [host3, ruleid1, grp3, rule:[[snippet1], [snippet2], [snippet3], ..]]
	//  [host3, ruleid2, grp2, rule:[[snippet1], ..]]
	//    and so on ...
	//  A snippet is of this form :
	//  [userattr, operator, const, type, isArray] where
	//  type == "string", "boolean", "number"
	//  isArray == "true" or "false"
	//  operator values are ==, !=, >, <, >=, <=

	// Read host rules collection for all rules of all hosts.
	// Find unique hostids and rule ids.
	// Accumulate snippets for each host rule and then process
	// each host rule.
	var hostMap map[string][]string  // key = hostid
	var ridMap map[string][][]string // key = hostid:rid

	hostMap = make(map[string][]string, 0)
	ridMap = make(map[string][][]string, 0)
	verInfo := ""
	tagneeded := false

	RetVal := make([]string, 2)
	RegoPolicy := generateRoutePolicyHeader()
	allRules := DBFindHostRules(tenant, "all", "")
	// We have all rules for all hosts
	for _, subrule := range allRules {
		// A subrule is a collection of snippets (match expressions)
		// for a group within a rule for a host
		// First check if we've seen this host. Since we prefix route
		// tag to host, split it out first to get untagged hostid.
		taggedHost := strings.SplitN(subrule.Host, ".", 2)
		hostid := taggedHost[1]
		rids, found1 := hostMap[hostid]
		if found1 {
			// Known host id. rids contains rule ids known so far
			// for this host. Check if the rule id is new or
			// known.
			found2 := false
			for _, rid := range rids {
				if rid == subrule.Rid {
					found2 = true
					break
				}
			}
			if !found2 {
				// new rule id found for host
				hostMap[hostid] = append(hostMap[hostid], subrule.Rid)
				tagneeded = true
			}
		} else {
			// New host id, so track host and rule ids.
			hostMap[hostid] = append(hostMap[hostid], subrule.Rid)
			tagneeded = true
		}
		// Consolidate all the snippets from the group into the rule
		rid := subrule.Rid
		for i := 0; i < len(subrule.Rule); i++ {
			ridMap[hostid+":"+rid] = append(ridMap[hostid+":"+rid], subrule.Rule[i])
		}
		// The tag for a host route is being included as a snippet in every rule by the ux code
		// It will be changed to instead prefix the hostid with the tag. We therefore need
		// this piece of code to check if the hostid is prefixed with the tag, and if so,
		// extract the tag to create a new snippet per rule.
		if tagneeded {
			tagneeded = false
			tagsnip := []string{"tag", "==", taggedHost[0], "string", "false"}
			ridMap[hostid+":"+rid] = append(ridMap[hostid+":"+rid], tagsnip)
		}
		grp := subrule.Group
		ver := fmt.Sprintf("%d", subrule.Version)
		verInfo = verInfo + "# Rule: " + rid + ", Group: " + grp + ", Version: " + ver + "\n"
	}
	RegoPolicy += verInfo + "\n"

	// Now we have maps of unique hostid and rid values
	// Loop through the maps to accumulate all snippets for a host
	// rule and then process the rule.
	for host, rids := range hostMap {
		// For each rule for a given host
		for _, rid := range rids {
			var hostRuleData [][]string
			hostRuleData = ridMap[host+":"+rid]
			if len(hostRuleData) < 1 {
				// This rule is empty ! Skip
				continue
			}
			Rule, errstr := processHostRule(host, hostRuleData)
			if errstr == "" {
				// No error. Accumulate the Rego code for the rule.
				RegoPolicy = RegoPolicy + Rule
			} else {
				RetVal[0] = errstr
				RetVal[1] = ""
				return RetVal
			}
		}
	}
	RetVal[0] = "ok"
	RetVal[1] = RegoPolicy
	return RetVal
}

func generateRoutePolicyHeader() string {
	return "package user.routing\ndefault route_tag = \"\"\n\n"
}

func processHostRule(host string, hostRule [][]string) (string, string) {
	routePolicyTag := ""
	routeTagValue := "deny"
	routeTagSpecified := false
	Exprs := ""
	RuleStart := "route_tag = rtag {\n"
	HostConst := "    input.host == \"" + host + "\"\n"
	for _, snippet := range hostRule {
		// snippet is an array of strings
		spl, ltoken := isSnippetLeftTokenSpecial(snippet)
		// Special token can be "tag" or "uid" but not "attrlist"
		if spl && (ltoken == "attrlist") {
			return "", "Invalid snippet in App Route rule"
		}
		optoken := getSnippetOpToken(snippet)
		uatype := strings.ToLower(getSnippetLeftTokenType(snippet))
		rtoken := getSnippetRightToken(snippet)
		rtokenarray := []string{""}

		// Do some pre-processing on rtoken to figure out more details.
		// rtoken is always a constant. Could be single value or array
		// of values.
		// Single value can have wild card if string type. Support only '*'
		// for now, with delimiter as '.'.
		// Multiple values can be entered as [x y z] or [x,y,z] or [x, y, z]
		// For string values, add double quotes if missing.
		// Always trim all values.
		// For processing array of values, first replace any comma with a
		// space, then split based on space. Remove any null strings to
		// compress array.
		// To search for anything other than a word or whitespace, use
		// 'const regex = /[^\w\s]/g' if using regexp matching (future).

		haswildcard := false
		issingle := true
		lts := "[_]"
		if !isSnippetLeftTokenMultiValue(snippet) {
			lts = ""
		}
		rts := "array[_]"

		if ltoken == "tag" {
			if !routeTagSpecified {
				routeTagValue = strings.Trim(rtoken, " ")
				routeTagSpecified = true
			}
		} else if uatype == "string" {
			// User attribute is string type. rtoken must be a string or
			// string array. Or else, right token contains user ids.
			if strings.Contains(rtoken, ",") {
				rtoken = strings.ReplaceAll(rtoken, ",", " ")
			}
			rtoken = strings.Trim(rtoken, " ")
			if strings.Contains(rtoken, " ") {
				// Seems to be case of multiple string values
				issingle = false
				rtokenarray = rightTokenArray(rtoken, "string")
			}
			if issingle {
				haswildcard = checkWildCard(rtoken)
				if !strings.HasPrefix(rtoken, "\"") {
					rtoken = "\"" + rtoken
				}
				if !strings.HasSuffix(rtoken, "\"") {
					rtoken += "\""
				}
			}
		} else {
			// right token contains user attribute value(s) which are not
			// string type
			if strings.Contains(rtoken, ",") {
				rtoken = strings.ReplaceAll(rtoken, ",", " ")
			}
			rtoken = strings.Trim(rtoken, " ")
			if strings.Contains(rtoken, " ") {
				// Seems to be case of multiple non-string values
				issingle = false
				rtokenarray = rightTokenArray(rtoken, uatype)
			}
		}
		if issingle {
			rts = ""
		}
		if ltoken == "tag" {
			routePolicyTag = "    rtag := \"" + routeTagValue + "\"\n"
		} else if ltoken == "uid" {
			// ltoken is user id
			if !issingle {
				// We have an array of values to match this attribute
				Exprs += processArray("uid", rtokenarray, optoken, "")
			} else {
				// We have a single value to match
				if haswildcard {
					// glob.match("*foo.com", [], input.user.uid)
					Exprs += processWildCard("uid", rtoken, optoken, "")
				} else {
					Exprs += "    input.user.uid " + optoken + " " + rtoken + "\n"
				}
			}
		} else {
			// ltoken is a user attribute.
			// It could be matched with a single value, or with multiple
			// values. If single value, it could have a wildcard.
			if !issingle {
				// We have an array of values to match this attribute
				Exprs += processArray(ltoken, rtokenarray, optoken, lts)
			} else {
				// We have a single value to match
				if haswildcard && (uatype == "string") {
					Exprs += processWildCard(ltoken, rtoken, optoken, lts)
				} else {
					Exprs += "    input.user." + ltoken + lts
					Exprs += " " + optoken + " " + rtoken + rts + "\n"
				}
			}
		}
	}
	if routePolicyTag == "" {
		return "", "Route tag not found for App " + host
	}
	RuleEnd := "}\n\n"
	Rule := RuleStart + HostConst + Exprs + routePolicyTag + RuleEnd
	return Rule, ""
}

// ------------------Trace Policy generation functions-------------------------

func dbGeneratePolicyFromTraceReqRules(tenant string) []string {
	// Trace policy generation
	// existingRules contains data in this format :
	//  [ruleid1, grp1, rule:[[snippet1], [snippet2], [snippet3], ..]]
	//  [ruleid2, grp1, rule:[[snippet1], [snippet2], ..]]
	//  [ruleid3, grp2, rule:[[snippet1], [snippet2], ..]]
	//  [ruleid4, grp3, rule:[[snippet1], [snippet2], [snippet3], ..]]
	//    and so on ...
	//  A snippet is of this form :
	//  [userattr, operator, const, type, isArray] where
	//  type == "string", "boolean", "number"
	//  isArray == "true" or "false"
	//  operator values are ==, !=, >, <, >=, <=
	//  The snippet that has the user attributes selected per group is
	//  ["XXX Attributes", operator, "attr1, attr2, ...", "string", "true"]

	var ridMap map[string][][]string // key = rid
	ridMap = make(map[string][][]string, 0)
	verInfo := ""

	RetVal := make([]string, 2)
	RegoPolicy := generateTraceReqPolicyHeader()
	// Read host rules collection for all rules of all hosts.
	// Find unique hostids and rule ids.
	// Accumulate snippets for each host rule and then process
	// each host rule.
	allRules := DBFindTraceReqRules(tenant, "all")
	// We have all rules for all trace reqs
	for _, subrule := range allRules {
		// A subrule is a collection of snippets (match expressions)
		// for a group within a rule for a host
		rid := subrule.Rid
		// Consolidate all the snippets from the group into the rule
		for i := 0; i < len(subrule.Rule); i++ {
			ridMap[rid] = append(ridMap[rid], subrule.Rule[i])
		}
		grp := subrule.Group
		ver := fmt.Sprintf("%d", subrule.Version)
		verInfo = verInfo + "# Rule: " + rid + ", Group: " + grp + ", Version: " + ver + "\n"
	}
	RegoPolicy += verInfo + "\n"

	// Now we have a map of unique trace reqs.
	// Loop through the map to accumulate all snippets for a trace
	// req rule and then process the rule.
	ruleIdx := 0
	for rid, truleData := range ridMap {
		// For each rule
		if len(truleData) < 1 {
			// This rule is empty ! Skip
			continue
		}
		Rule, errstr := processTraceReqRule(rid, truleData, ruleIdx)
		if errstr == "" {
			// No error. Accumulate the Rego code for the rule.
			RegoPolicy = RegoPolicy + Rule
		} else {
			RetVal[0] = errstr
			RetVal[1] = ""
			return RetVal
		}
		ruleIdx++
	}
	RetVal[0] = "ok"
	RetVal[1] = RegoPolicy
	return RetVal
}

func generateTraceReqPolicyHeader() string {
	return "package user.tracing\ndefault request = {\"no\": [\"\"]}\n\n"
}

func processTraceReqRule(rid string, traceRule [][]string, ruleIndex int) (string, string) {
	attrSpecified := false
	traceReqPolicyAttr := "** Error **"
	traceReqAttrValue := ""
	traceReq := "{\"" + rid + "\": "
	Exprs := ""
	ruleIndex += 1
	RuleId := "traceid" + strconv.Itoa(ruleIndex)
	RuleStart := "request = " + RuleId + " {\n"
	if ruleIndex > 1 {
		RuleStart = " else = " + RuleId + " {\n"
	}
	i := 0
	for _, snippet := range traceRule {
		spl, ltoken := isSnippetLeftTokenSpecial(snippet)
		// Special token can be "uid" or "attrlist", not "tag"
		if spl && (ltoken == "tag") {
			return "", "Invalid snippet in Trace req rule"
		}
		optoken := getSnippetOpToken(snippet)
		uatype := strings.ToLower(getSnippetLeftTokenType(snippet))
		rtoken := getSnippetRightToken(snippet)
		rtokenarray := []string{""}

		// Do some pre-processing on rtoken to figure out more details.
		// rtoken is always a constant. Could be single value or array
		// of values.
		// Single value can have wild card if string type. Support only '*'
		// for now, with delimiter as '.'.
		// Multiple values can be entered as [x y z] or [x,y,z] or [x, y, z]
		// For string values, add double quotes if missing.
		// Always trim all values.
		// For processing array of values, first replace any comma with a
		// space, then split based on space. Remove any null strings to
		// compress array.
		// To search for anything other than a word or whitespace, use
		// 'const regex = /[^\w\s]/g' if using regexp matching (future).

		haswildcard := false
		issingle := true
		lts := "[_]"
		if !isSnippetLeftTokenMultiValue(snippet) {
			lts = ""
		}
		rts := "array[_]"

		if ltoken == "attrlist" {
			if strings.Contains(rtoken, ",") {
				rtoken = strings.ReplaceAll(rtoken, ",", " ")
			}
			rtoken = strings.Trim(rtoken, " ")
			var attrarray []string
			attrarray = rightTokenArray(rtoken, "string")
			cumattrs := ""
			for _, attr := range attrarray {
				if i > 0 {
					cumattrs += ", "
				}
				cumattrs += attr
				i++
			}
			traceReqAttrValue += cumattrs
			attrSpecified = true
		} else if uatype == "string" {
			// User attribute is string type. rtoken must be a string or
			// string array. Or else, right token contains user ids.
			if strings.Contains(rtoken, ",") {
				rtoken = strings.ReplaceAll(rtoken, ",", " ")
			}
			rtoken = strings.Trim(rtoken, " ")
			if strings.Contains(rtoken, " ") {
				// Seems to be case of multiple string values
				issingle = false
				rtokenarray = rightTokenArray(rtoken, "string")
			}
			if issingle {
				haswildcard = checkWildCard(rtoken)
				if !strings.HasPrefix(rtoken, "\"") {
					rtoken = "\"" + rtoken
				}
				if !strings.HasSuffix(rtoken, "\"") {
					rtoken += "\""
				}
			}
		} else {
			// right token contains user attribute value(s) which are not
			// string type
			if strings.Contains(rtoken, ",") {
				rtoken = strings.ReplaceAll(rtoken, ",", " ")
			}
			rtoken = strings.Trim(rtoken, " ")
			if strings.Contains(rtoken, " ") {
				// Seems to be case of multiple non-string values
				issingle = false
				rtokenarray = rightTokenArray(rtoken, uatype)
			}
		}
		if issingle {
			rts = ""
		}
		if ltoken == "attrlist" {
			// Nothing more needs to be done
		} else if ltoken == "uid" {
			// right token contains one or more user ids
			if !issingle {
				// We have an array of values to match this attribute
				Exprs += processArray("uid", rtokenarray, optoken, "")
			} else {
				// We have a single value to match
				if haswildcard {
					// glob.match("*foo.com", [], input.user.uid)
					Exprs += processWildCard("uid", rtoken, optoken, "")
				} else {
					Exprs += "    input.user.uid " + optoken + " " + rtoken + "\n"
				}
			}
		} else {
			// ltoken is a user attribute name.
			// It could be matched with a single value, or with multiple
			// values. If single value, it could have a wildcard.
			if !issingle {
				// We have an array of values to match this attribute
				Exprs += processArray(ltoken, rtokenarray, optoken, lts)
			} else {
				// We have a single value to match
				if haswildcard && (uatype == "string") {
					Exprs += processWildCard(ltoken, rtoken, optoken, lts)
				} else {
					Exprs += "    input.user." + ltoken + lts
					Exprs += " " + optoken + " " + rtoken + rts + "\n"
				}
			}
		}
	}
	if !attrSpecified {
		traceReqAttrValue = "\"all\""
	}
	traceReq = traceReq + "[" + traceReqAttrValue + "]}\n"
	traceReqPolicyAttr = "    " + RuleId + " := " + traceReq
	RuleEnd := "}"
	Rule := RuleStart + Exprs + traceReqPolicyAttr + RuleEnd
	return Rule, ""
}

// ------------------Stats Policy generation functions-------------------------

func dbGeneratePolicyFromStatsRule(tenant string) []string {
	// Stats policy generation
	// existingRule contains data in this format :
	//  [ruleid, rule:[[snippet]]]
	//  where ruleid = "StatsRule"
	//  snippet is of this form (per group):
	//  ["XXX Attributes", operator, [list of attribute names], "string", "true"] where
	//  operator is either == or !=

	var ridMap map[string][][]string // key = rid
	ridMap = make(map[string][][]string, 0)
	verInfo := ""

	RetVal := make([]string, 2)
	RegoPolicy := generateStatsPolicyHeader()
	allRules := DBFindStatsRule(tenant)
	for _, subrule := range allRules {
		// A subrule is a collection of snippets (match expressions)
		// for a group within a rule for a host
		rid := subrule.Rid
		// Consolidate all the snippets from the group into the rule
		for i := 0; i < len(subrule.Rule); i++ {
			ridMap[rid] = append(ridMap[rid], subrule.Rule[i])
		}
		grp := subrule.Group
		ver := fmt.Sprintf("%d", subrule.Version)
		verInfo = verInfo + "# Rule: " + rid + ", Group: " + grp + ", Version: " + ver + "\n"
	}
	RegoPolicy += verInfo + "\n"

	for _, sruleData := range ridMap {
		// For each rule
		if len(sruleData) < 1 {
			// This rule is empty ! Skip
			continue
		}
		Rule, errstr := processStatsRule(sruleData)
		if errstr == "" {
			// No error. Accumulate the Rego code for the rule.
			RegoPolicy = RegoPolicy + Rule
		} else {
			RetVal[0] = errstr
			RetVal[1] = ""
			return RetVal
		}
	}

	RetVal[0] = "ok"
	RetVal[1] = RegoPolicy
	return RetVal
}

func generateStatsPolicyHeader() string {
	return "package user.stats\ndefault attributes = {\"exclude\": [\"all\"]}\n\n"
}

func processStatsRule(statsRule [][]string) (string, string) {
	statsDefaultAttrList := "\"all\""
	attrList := ""
	RuleStart := ""
	statsPolicyAttr := ""
	RuleEnd := ""
	snippetFound := false
	i := 0
	for _, snippet := range statsRule {
		snippetFound = true
		spl, ltoken := isSnippetLeftTokenSpecial(snippet)
		// Left token has to be special and has to be "attrlist"
		if !spl || (ltoken != "attrlist") {
			return "", "Invalid snippet in Stats rule"
		}

		// rtoken is always a string with one or more attribute names
		// separated by space or maybe comma. Break out names and add
		// double quote for each name.

		rtoken := getSnippetRightToken(snippet)
		if strings.Contains(rtoken, ",") {
			rtoken = strings.ReplaceAll(rtoken, ",", " ")
		}
		rtoken = strings.Trim(rtoken, " ")
		var attrarray []string
		attrarray = rightTokenArray(rtoken, "string")
		cumattrs := ""
		for _, attr := range attrarray {
			if i > 0 {
				cumattrs += ", "
			}
			cumattrs += attr
			i++
		}
		attrList += cumattrs
	}
	RuleStart = "attributes = select {\n"
	if snippetFound {
		attrList = "{\"include\": [" + attrList + "]}\n"
	} else {
		attrList = "{\"include\": [" + statsDefaultAttrList + "]}\n"
	}
	statsPolicyAttr = "    select := " + attrList
	RuleEnd = "}"
	Rule := RuleStart + statsPolicyAttr + RuleEnd
	return Rule, ""
}

// Common functions for policy generation from rule snippets

func getSnippetLeftToken(snippet []string) string {
	return snippet[0]
}

func getSnippetRightToken(snippet []string) string {
	return snippet[2]
}

func getSnippetOpToken(snippet []string) string {
	return snippet[1]
}

func getSnippetLeftTokenType(snippet []string) string {

	spl, _ := isSnippetLeftTokenSpecial(snippet)
	if spl {
		return "string"
	}
	return snippet[3]
}

func isSnippetLeftTokenSpecial(snippet []string) (bool, string) {
	if snippet[0] == "User ID" {
		return true, "uid"
	}
	if snippet[0] == "tag" {
		return true, "tag"
	}
	if strings.HasSuffix(snippet[0], " Attributes") {
		return true, "attrlist"
	}
	ltok := getSnippetLeftToken(snippet)
	return false, ltok
}

func isSnippetLeftTokenMultiValue(snippet []string) bool {
	spl, _ := isSnippetLeftTokenSpecial(snippet)
	if !spl {
		if snippet[4] == "true" {
			return true
		} else {
			return false
		}
	}
	return false
}

func rightTokenArray(rtok string, uatype string) []string {
	rtokenarray := strings.Split(rtok, " ")
	// Now remove null string elements from array
	var newarray []string
	rtoken1 := ""
	for i := 0; i < len(rtokenarray); i++ {
		rtoken1 = strings.TrimSpace(rtokenarray[i])
		if len(rtoken1) > 0 {
			if uatype == "string" {
				if !strings.HasPrefix(rtoken1, "\"") {
					rtoken1 = "\"" + rtoken1
				}
				if !strings.HasSuffix(rtoken1, "\"") {
					rtoken1 += "\""
				}
			} else if uatype == "number" {
				if strings.Contains(rtoken1, "\"") {
					rtoken1 = strings.ReplaceAll(rtoken1, "\"", " ")
					rtoken1 = strings.TrimSpace(rtoken1)
				}
			}
			newarray = append(newarray, rtoken1)
		}
	}
	return newarray
}

func checkWildCard(rtok string) bool {
	if strings.Contains(rtok, "*") {
		return true
	}
	if strings.Contains(rtok, "?") {
		return true
	}
	if strings.Contains(rtok, "[") && strings.Contains(rtok, "]") {
		return true
	}
	return false
}

func processWildCard(ltok string, rtok string, op string, lts string) string {
	Mexpr := "glob.match(" + rtok + ", [], input.user." + ltok + lts
	if op == "==" {
		Mexpr = "    " + Mexpr + ")\n"
	} else {
		Mexpr = "    !" + Mexpr + ")\n"
	}
	return Mexpr
}

func processArray(ltok string, rtarray []string, op string, lts string) string {
	// When optoken is ==, we need
	//   foobararray := [value1, value2, value3, ..]
	//   input.user.uid == foobararray[_]
	// When optoken is !=, we need
	//   input.user.uid != value1
	//   input.user.uid != value2 and so on
	// Logical OR for == changes to logical AND for !=
	Aexpr := ""
	if op == "!=" {
		for i := 0; i < len(rtarray); i++ {
			Aexpr += "    input.user." + ltok + lts + " != " + rtarray[i] + "\n"
		}
	} else {
		Aexpr = "    " + ltok + "array := ["
		for i := 0; i < len(rtarray); i++ {
			if i > 0 {
				Aexpr += ", "
			}
			Aexpr += rtarray[i]
		}
		Aexpr += "]\n"
		Aexpr += "    input.user." + ltok + lts + " == " + ltok + "array[_]\n"
	}
	return Aexpr
}
