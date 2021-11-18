package db

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

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

	if DBFindTenant(uuid) == nil {
		return fmt.Errorf("Cant find tenant %s", uuid)
	}
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

type BundleAccessRule struct {
	Bid  string     `json:"bid" bson:"bid"`
	Rid  string     `json:"rid" bson:"rid"`
	Rule [][]string `json:"rule" bson:"rule"`
}

// This API will add a new bundle rule or update a bundle rule if it already exists
func DBAddBundleRule(uuid string, data *BundleAccessRule) error {

	if DBFindTenant(uuid) == nil {
		return fmt.Errorf("Cant find tenant %s", uuid)
	}
	Id := data.Bid + ":" + data.Rid

	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	bundleRuleCltn := dbGetCollection(uuid, "NxtBundleRules")
	if bundleRuleCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	err := bundleRuleCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": Id},
		bson.D{
			{"$set", bson.M{"rule": data.Rule, "rid": data.Rid, "bid": data.Bid}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindBundleRule(tenant string, Id string) *BundleAccessRule {
	var rule BundleAccessRule

	bundleRuleCltn := dbGetCollection(tenant, "NxtBundleRules")
	if bundleRuleCltn == nil {
		return nil
	}
	err := bundleRuleCltn.FindOne(
		context.TODO(),
		bson.M{"_id": Id},
	).Decode(&rule)
	if err != nil {
		return nil
	}
	return &rule
}

func DBFindAllBundleRules(tenant string) []BundleAccessRule {
	var rules []BundleAccessRule

	bundleRuleCltn := dbGetCollection(tenant, "NxtBundleRules")
	if bundleRuleCltn == nil {
		return nil
	}
	cursor, err := bundleRuleCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &rules)
	if err != nil {
		return nil
	}

	return rules
}

func DBDelBundleRule(tenant string, bid string, ruleid string) error {
	bundleRuleCltn := dbGetCollection(tenant, "NxtBundleRules")
	if bundleRuleCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	id := bid + ":" + ruleid
	_, err := bundleRuleCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": id},
	)

	return err
}

//----------------------------------Host ID rules-----------------------------------
// Route Policy is generated from the rules for one or more host ids.
// Note that Route policy also supports host access control

type HostRouteRule struct {
	Host string     `json:"host" bson:"host"`
	Rid  string     `json:"rid" bson:"rid"`
	Rule [][]string `json:"rule" bson:"rule"`
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
func DBAddHostRule(uuid string, data *HostRouteRule) error {

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

func DBDelHostRule(tenant string, hostid string, ruleid string) error {
	hostRuleCltn := dbGetCollection(tenant, "NxtHostRules")
	if hostRuleCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	id := hostid + ":" + ruleid
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
