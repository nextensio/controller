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
	Majver   string             `json:"majver" bson:"majver"`
	Minver   string             `json:"minver" bson:"minver"`
	Tenant   primitive.ObjectID `json:"tenant" bson:"tenant"`
	Rego     string             `json:"rego" bson:"rego"`
}

// This API will add a new policy or update a policy if it already exists
func DBAddPolicy(data *Policy) error {

	if DBFindTenant(data.Tenant) == nil {
		return fmt.Errorf("Cant find tenant %s", data.Tenant)
	}
	// TODO: These versions have to be updated
	data.Majver = "1"
	data.Minver = "0"
	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := policyCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.PolicyId, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"_id": data.PolicyId, "tenant": data.Tenant, "rego": data.Rego,
				"majver": data.Majver, "minver": data.Minver}},
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

func DBDelPolicy(tenant primitive.ObjectID, policyId string) error {
	_, err := policyCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": policyId, "tenant": tenant},
	)

	return err
}
