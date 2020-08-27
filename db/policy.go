package db

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// NOTE: The bson decoder will not work if the structure field names dont start with upper case
type Policy struct {
	PolicyId string             `json:"pid" bson:"_id"`
	Tenant   primitive.ObjectID `json:"tenant" bson:"tenant"`
	Version  string             `json:"version" bson:"version"`
	OPA      string             `json:"policy" bson:"policy"`
}

// This API will add a new policy or update a policy if it already exists
func DBAddPolicy(data *Policy) error {

	if DBFindTenant(data.Tenant) == nil {
		return fmt.Errorf("Cant find tenant %s", data.Tenant)
	}
	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	// TODO: Version has to be set properly
	data.Version = "1"
	err := policyCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.PolicyId, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"_id": data.PolicyId, "tenant": data.Tenant, "version": data.Version, "policy": data.OPA}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindPolicy(tenant primitive.ObjectID, policyId string) *Policy {
	var policy Policy
	err := policyCltn.FindOne(
		context.TODO(),
		bson.M{"_id": policyId, "tenant": tenant},
	).Decode(&policy)
	if err != nil {
		return nil
	}
	return &policy
}

func DBFindAllPolicies(tenant primitive.ObjectID) []Policy {
	var policies []Policy

	cursor, err := policyCltn.Find(context.TODO(), bson.M{"tenant": tenant})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &policies)
	if err != nil {
		return nil
	}

	return policies
}
