package db

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var bungrpLock sync.RWMutex
var apolLock sync.Mutex

// NOTE: The bson decoder will not work if the structure field names dont start with upper case
type Policy struct {
	PolicyId string `json:"pid" bson:"_id"`
	ChangeBy string `json:"changeby" bson:"changeby"`
	ChangeAt string `json:"changeat" bson:"changeat"`
	Majver   int    `json:"majver" bson:"majver"`
	Minver   int    `json:"minver" bson:"minver"`
	Rego     []rune `json:"rego" bson:"rego"`
}

// This API will add a new policy or update a policy if it already exists
func DBAddPolicy(uuid string, admin string, data *Policy) error {

	t := DBFindTenant(uuid)
	if t == nil {
		return fmt.Errorf("Cannot find tenant %s", uuid)
	}
	// Temporarily disable this to allow create.sh to create local testbed
	//if t.EasyMode {
	//	return fmt.Errorf("A policy cannot be added directly in Easy Mode")
	//}
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
	// Temporarily disable this to allow create.sh to create local testbed
	//if t.EasyMode {
	//	return fmt.Errorf("A policy cannot be deleted directly in Easy Mode")
	//}
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

//----------------------------------Bundle ID rules-----------------------------------
// Access Policy is generated from the rules for one or more bundle ids

// Validate that the rule snippets contain only attributes owned by the
// specified group.
// The filter is a temporary hack to filter out snippets for attributes
// owned by the group and ignore all other snippets. This is only for
// backward compatibility until the controller UI is changed. Rule snippets
// pushed during an add or update should be only for the specified group
// instead of all snippets in the rule.
func dbValidateGroupOwnership(tenant string, rule *[][]string, appliesto string, key string, group string, filter bool) (bool, [][]string) {
	var filtSnip [][]string

	// Get all user attributes from AttrSet
	// For each snippet in rule, check if user attribute ownership as
	// per AttrSet matches group
	if len(*rule) < 1 {
		// There are no snippets in the rule
		glog.Errorf("ValidateGroupRule: rule length 0")
		return false, filtSnip
	}
	noattrs := true
	usrattrs := DBFindSpecificAttrSet(tenant, appliesto, group)
	if usrattrs != nil {
		// We have user attributes defined, so turn flag off
		noattrs = false
	}
	for _, snip := range *rule {
		if snip[0] == key {
			if noattrs {
				// If there are no user attributes defined and rule
				// contains only uid, accept it by returning true,
				// else return false.
				if len(*rule) > 1 {
					glog.Errorf("ValidateGroupRule: rule contains undefined attributes")
					return false, filtSnip
				} else {
					filtSnip = append(filtSnip, snip)
					glog.Infof("ValidateGroupRule: no attributes but added %v", snip)
					return true, filtSnip
				}
			}
			// There are user attributes defined, so we continue checking
			continue
		}
		// Attribute found in snippet is not userid. Check if attribute
		// belongs to group. If no user attributes defined, return false.
		if noattrs {
			glog.Errorf("ValidateGroupRule: no attributes defined rule contains attributes")
			return false, filtSnip
		}
		found := false
		// Search in our AttrSet and if found, ensure the atrribute belongs
		// to the specified group. If not found, return false
		for _, attr := range usrattrs {
			if attr.Name == snip[0] {
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
	return (len(filtSnip) > 0), filtSnip
}

// A rule is configured for a bundle. The rule can be composed of
// sub-rules for one or more groups. Each sub-rule is a collection
// of one or more match expressions (called snippets).
// The key is composed of Bid, Rid and Group fields concatenated
// together with ":".
// Version tracks the version of each sub-rule and is used to
// implement locking if multiple admins try to update the same sub-rule.
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
func DBAddBundleRuleGroup(uuid string, group string, data *BundleAccessRule) error {

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
	sts, newsnips := dbValidateGroupOwnership(uuid, &data.Rule, "Users", "uid", group, true)
	if !sts {
		return fmt.Errorf("Bundle rule group has attributes not belonging to group")
	}
	bundleRuleCltn := dbGetCollection(uuid, "NxtBundleRules")
	if bundleRuleCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
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
	} else if bunrul.Version != data.Version {
		// Update case. Cannot update if version has changed
		return fmt.Errorf("Bundle rule has changed in DB. Refresh rule and try again")
	} else {
		data.Version++
	}
	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := bundleRuleCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": Id},
		bson.D{
			{"$set", bson.M{"rule": newsnips, "rid": data.Rid, "bid": data.Bid,
				"group": data.Group, "admin": data.Admin, "version": data.Version}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
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

// Gets all complete rules for a specific bundle. If bundle id is specified as
// "all", get rules for all bundles.
func DBFindBundleAllRules(tenant string, bid string) []BundleAccessRule {
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
		cursor, err = bundleRuleCltn.Find(context.TODO(), bson.M{"bid": bid})
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

// Gets a specific complete rule for a specific bundle
func DBFindAllGroupsForBundleRule(tenant string, bid string, rid string) []BundleAccessRule {
	var rules []BundleAccessRule

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
	cursor, err := bundleRuleCltn.Find(context.TODO(), bson.M{"bid": bid, "rid": rid})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &rules)
	if err != nil {
		return nil
	}

	return rules
}

// Gets all complete rules for all bundles
func dbFindAllBundleRules(tenant string) []BundleAccessRule {
	return DBFindBundleAllRules(tenant, "all")
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

type LockHostRouteRule struct {
	Host  string `json:"host" bson:"host"`
	Rid   string `json:"rid" bson:"rid"`
	Group string `json:"group" bson:"group"`
}

func DBLockHostRule(uuid string, group string, data *LockHostRouteRule) error {

	if DBFindTenant(uuid) == nil {
		return fmt.Errorf("Cant find tenant %s", uuid)
	}
	Id := data.Host + ":" + data.Rid

	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	hostRuleCltn := dbGetCollection(uuid, "NxtHostRules")
	if hostRuleCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}

	err := hostRuleCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": Id},
		bson.D{
			{"$set", bson.M{"group": data.Group}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

type HostRouteRule struct {
	Host  string     `json:"host" bson:"host"`
	Rid   string     `json:"rid" bson:"rid"`
	Rule  [][]string `json:"rule" bson:"rule"`
	Group string     `json:"group" bson:"group"`
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

// This API will add a new host rule or update a host rule if it already exists
func DBAddHostRule(uuid string, group string, data *HostRouteRule) error {

	if DBFindTenant(uuid) == nil {
		return fmt.Errorf("Cant find tenant %s", uuid)
	}
	Id := data.Host + ":" + data.Rid
	exists := DBFindHostRule(uuid, Id)
	if exists != nil {
		if exists.Group != "" && exists.Group != group {
			return fmt.Errorf("Rule is locked by group %s", exists.Group)
		}
	}
	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	hostRuleCltn := dbGetCollection(uuid, "NxtHostRules")
	if hostRuleCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}

	err := hostRuleCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": Id},
		bson.D{
			{"$set", bson.M{"rule": data.Rule, "rid": data.Rid, "host": data.Host}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindHostRule(tenant string, Id string) *HostRouteRule {
	var rule HostRouteRule

	hostRuleCltn := dbGetCollection(tenant, "NxtHostRules")
	if hostRuleCltn == nil {
		return nil
	}
	err := hostRuleCltn.FindOne(
		context.TODO(),
		bson.M{"_id": Id},
	).Decode(&rule)
	if err != nil {
		return nil
	}
	return &rule
}

func DBFindAllHostRules(tenant string) []HostRouteRule {
	var rules []HostRouteRule

	hostRuleCltn := dbGetCollection(tenant, "NxtHostRules")
	if hostRuleCltn == nil {
		return nil
	}
	cursor, err := hostRuleCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &rules)
	if err != nil {
		return nil
	}
	return rules
}

func DBDelHostRule(tenant string, group string, hostid string, ruleid string) error {
	hostRuleCltn := dbGetCollection(tenant, "NxtHostRules")
	if hostRuleCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	id := hostid + ":" + ruleid
	exists := DBFindHostRule(tenant, id)
	if exists != nil {
		if exists.Group != "" && exists.Group != group {
			return fmt.Errorf("Rule is locked by group %s", exists.Group)
		}
	}
	_, err := hostRuleCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": id},
	)

	return err
}

//----------------------------------TraceRequest rules-----------------------------------
// Trace Policy is generated from the rules for one or more trace requests

type TraceReqRule struct {
	Rid  string     `json:"rid" bson:"_id"`
	Rule [][]string `json:"rule" bson:"rule"`
}

// This API will add a new trace req rule or update a trace req rule if it already exists
func DBAddTraceReqRule(uuid string, data *TraceReqRule) error {

	if DBFindTenant(uuid) == nil {
		return fmt.Errorf("Cant find tenant %s", uuid)
	}

	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	traceReqRuleCltn := dbGetCollection(uuid, "NxtTraceReqRules")
	if traceReqRuleCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	err := traceReqRuleCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Rid},
		bson.D{
			{"$set", bson.M{"rule": data.Rule}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindTraceReqRule(tenant string, Id string) *TraceReqRule {
	var rule TraceReqRule

	traceReqRuleCltn := dbGetCollection(tenant, "NxtTraceReqRules")
	if traceReqRuleCltn == nil {
		return nil
	}
	err := traceReqRuleCltn.FindOne(
		context.TODO(),
		bson.M{"_id": Id},
	).Decode(&rule)
	if err != nil {
		return nil
	}
	return &rule
}

func DBFindAllTraceReqRules(tenant string) []TraceReqRule {
	var rules []TraceReqRule

	traceReqRuleCltn := dbGetCollection(tenant, "NxtTraceReqRules")
	if traceReqRuleCltn == nil {
		return nil
	}
	cursor, err := traceReqRuleCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &rules)
	if err != nil {
		return nil
	}

	return rules
}

func DBDelTraceReqRule(tenant string, ruleid string) error {
	traceReqRuleCltn := dbGetCollection(tenant, "NxtTraceReqRules")
	if traceReqRuleCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	_, err := traceReqRuleCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": ruleid},
	)

	return err
}

//----------------------------------Stats rule-----------------------------------
// Stats Policy is generated from a single rule called "StatsRule" that specifies the
// user attributes to be used as dimensions for the stats

type StatsRule struct {
	Rid  string     `json:"rid" bson:"_id"`
	Rule [][]string `json:"rule" bson:"rule"`
}

// This API will add a new stats rule or update stats rule if it already exists
func DBAddStatsRule(uuid string, data *StatsRule) error {

	if DBFindTenant(uuid) == nil {
		return fmt.Errorf("Cant find tenant %s", uuid)
	}

	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	statsRuleCltn := dbGetCollection(uuid, "NxtStatsRule")
	if statsRuleCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	err := statsRuleCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Rid},
		bson.D{
			{"$set", bson.M{"rule": data.Rule}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindAllStatsRules(tenant string) []StatsRule {
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

func DBDelStatsRule(tenant string, ruleid string) error {
	statsRuleCltn := dbGetCollection(tenant, "NxtStatsRule")
	if statsRuleCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	_, err := statsRuleCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": ruleid},
	)

	return err
}

//----------------------------Rules to policy conversion------------------------

// This code is only applicable in Easy Mode

func DBGeneratePolicyFromRules(tenant string, policyid string, admin string) error {
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
	//    to hold off on the policy generation. To keep it simple, return
	//    an error so that the operation can be retried after some time.
	// 3. two or more admins are not trying to generate the same policy
	//    in parallel. We don't want the output policy to get munged. So
	//    allow only one user to generate the same policy at a time.
	switch policyid {
	case "AccessPolicy":
		apolLock.Lock()
		defer apolLock.Unlock()
		res := dbGeneratePolicyFromBundleRules(tenant)
		if res[0] != "ok" {
			return fmt.Errorf(res[0])
		}
		policy := Policy{
			PolicyId: policyid,
		}
		policy.Rego = []rune(res[1])
		return dbAddPolicy(tenant, admin, &policy)
	default:
		return fmt.Errorf("Generate policy from rules - unknown/unsupported policy " + policyid)
	}
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

	var bidMap map[string][]string   // key = bid
	var ridMap map[string][][]string // key = bid:rid

	bidMap = make(map[string][]string, 0)
	ridMap = make(map[string][][]string, 0)
	verInfo := ""

	RetVal := make([]string, 2)
	RegoPolicy := generateAccessPolicyHeader()
	// Read bundle rules collection for all rules of all bundles.
	// Find unique bids and rule ids.
	// Accumulate snippets for each bundle rule and then process
	// each bundle rule.
	allRules := dbFindAllBundleRules(tenant)
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
			bid := subrule.Bid
			rid := subrule.Rid
			if !found2 {
				// new rule id found for bid
				bidMap[bid] = append(bidMap[bid], rid)
			}
			// Consolidate all the snippets from the group into the rule
			for i := 0; i < len(subrule.Rule); i++ {
				ridMap[bid+":"+rid] = append(ridMap[bid+":"+rid], subrule.Rule[i])
			}
			grp := subrule.Group
			ver := fmt.Sprintf("%d", subrule.Version)
			verInfo = verInfo + "# Rule: " + rid + ", Group: " + grp + ", Version: " + ver + "\n"
		} else {
			// New bundle id, so track bundle and rule ids.
			bid := subrule.Bid
			rid := subrule.Rid
			bidMap[bid] = append(bidMap[bid], rid)
			// Consolidate all the snippets from the group into the rule
			for i := 0; i < len(subrule.Rule); i++ {
				ridMap[bid+":"+rid] = append(ridMap[bid+":"+rid], subrule.Rule[i])
			}
			grp := subrule.Group
			ver := fmt.Sprintf("%d", subrule.Version)
			verInfo = verInfo + "# Rule: " + rid + ", Group: " + grp + ", Version: " + ver + "\n"
		}
	}
	RegoPolicy += verInfo + "\n"

	// Now we have maps of unique bid and rid values
	// Loop through the maps to accumulate all snippets for a bundle
	// rule.
	// For each bundle, get the rules
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
		ltoken := getRuleLeftToken(snippet)
		uavalue := getRuleTokenValue(ltoken, snippet)
		uatype := strings.ToLower(getRuleTokenType(snippet))
		rtoken := getRuleRightToken(snippet)
		rtokenarray := []string{""}
		optoken := getRuleOpToken(snippet)

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
		rts := "array[_]"

		rtoken = strings.Trim(rtoken, " ")
		if (uatype == "string") || (uavalue == "uid") {
			// User attribute is string type. rtoken must be a string or
			// string array
			if strings.Contains(rtoken, ",") {
				rtoken = strings.ReplaceAll(rtoken, ",", " ")
				rtoken = strings.Trim(rtoken, " ")
			}
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
			if strings.Contains(rtoken, ",") {
				rtoken = strings.ReplaceAll(rtoken, ",", " ")
				rtoken = strings.Trim(rtoken, " ")
			}
			if strings.Contains(rtoken, " ") {
				// Seems to be case of multiple non-string values
				issingle = false
				rtokenarray = rightTokenArray(rtoken, uatype)
			}
		}

		if issingle {
			rts = ""
		}
		if uavalue != "array" {
			lts = ""
		}
		if uavalue == "uid" {
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
			// ltoken is an array type user attribute
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

// ------------------Access Policy generation functions end----------------------

// Common functions for policy generation from rule snippets

func getRuleLeftToken(snippet []string) string {
	return snippet[0]
}

func getRuleRightToken(snippet []string) string {
	return snippet[2]
}

func getRuleOpToken(snippet []string) string {
	return snippet[1]
}

func getRuleTokenType(snippet []string) string {
	return snippet[3]
}

func getRuleTokenValue(name string, snippet []string) string {
	if name == "User ID" {
		return "uid"
	}
	if snippet[4] == "true" {
		return "array"
	} else {
		return "single"
	}
}

func rightTokenArray(rtok string, uatype string) []string {
	rtokenarray := strings.Split(rtok, " ")
	// Now remove null string elements from array
	var newarray []string
	j := 0
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
			newarray[j] = rtoken1
			j++
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
