package db

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// NOTE: The bson decoder will not work if the structure field names dont start with upper case
type Policy struct {
	PolicyId string `json:"pid" bson:"_id"`
	Majver   int    `json:"majver" bson:"majver"`
	Minver   int    `json:"minver" bson:"minver"`
	Rego     []rune `json:"rego" bson:"rego"`
}

// This API will add a new policy or update a policy if it already exists
func DBAddPolicy(uuid string, data *Policy) error {

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
	err := policyCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.PolicyId},
		bson.D{
			{"$set", bson.M{"_id": data.PolicyId, "rego": data.Rego,
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

type DBBundleAccessRule struct {
	Id   string `json:"id" bson:"_id"` // Bundle-id:Rule-id
	Bid  string `json:"bid" bson:"bid"`
	Rid  string `json:"rid" bson:"rid"`
	Rule string `json:"rule" bson:"rule"`
}

type BundleAccessRule struct {
	Bid  string `json:"bid" bson:"bid"`
	Rid  string `json:"rid" bson:"rid"`
	Rule string `json:"rule" bson:"rule"`
}

// This API will add a new bundle rule or update a bundle rule if it already exists
func DBAddBundleRule(uuid string, data *BundleAccessRule) error {
	var rule DBBundleAccessRule

	if DBFindTenant(uuid) == nil {
		return fmt.Errorf("Cant find tenant %s", uuid)
	}
	rule.Id = data.Bid + ":" + data.Rid
	rule.Bid = data.Bid
	rule.Rid = data.Rid
	rule.Rule = data.Rule

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
		bson.M{"_id": rule.Id},
		bson.D{
			{"$set", bson.M{"rule": rule.Rule, "rid": rule.Rid}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindBundleRule(tenant string, Id string) *BundleAccessRule {
	var dbrule DBBundleAccessRule
	var rule BundleAccessRule

	bundleRuleCltn := dbGetCollection(tenant, "NxtBundleRules")
	if bundleRuleCltn == nil {
		return nil
	}
	err := bundleRuleCltn.FindOne(
		context.TODO(),
		bson.M{"_id": Id},
	).Decode(&dbrule)
	if err != nil {
		return nil
	}
	rule.Bid = dbrule.Bid
	rule.Rid = dbrule.Rid
	rule.Rule = dbrule.Rule
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

type DBHostRouteRule struct {
	Id   string `json:"id" bson:"_id"` // Host-id:Rule-id
	Host string `json:"host" bson:"host"`
	Rid  string `json:"rid" bson:"rid"`
	Rule string `json:"rule" bson:"rule"`
}

type HostRouteRule struct {
	Host string `json:"host" bson:"host"`
	Rid  string `json:"rid" bson:"rid"`
	Rule string `json:"rule" bson:"rule"`
}

// This API will add a new host rule or update a host rule if it already exists
func DBAddHostRule(uuid string, data *HostRouteRule) error {
	var rule DBHostRouteRule

	if DBFindTenant(uuid) == nil {
		return fmt.Errorf("Cant find tenant %s", uuid)
	}
	rule.Id = data.Host + ":" + data.Rid
	rule.Host = data.Host
	rule.Rid = data.Rid
	rule.Rule = data.Rule

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
		bson.M{"_id": rule.Id},
		bson.D{
			{"$set", bson.M{"rule": rule.Rule, "rid": rule.Rid}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindHostRule(tenant string, Id string) *HostRouteRule {
	var dbrule DBHostRouteRule
	var rule HostRouteRule

	hostRuleCltn := dbGetCollection(tenant, "NxtHostRules")
	if hostRuleCltn == nil {
		return nil
	}
	err := hostRuleCltn.FindOne(
		context.TODO(),
		bson.M{"_id": Id},
	).Decode(&dbrule)
	if err != nil {
		return nil
	}
	rule.Host = dbrule.Host
	rule.Rid = dbrule.Rid
	rule.Rule = dbrule.Rule
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
