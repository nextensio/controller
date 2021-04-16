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
