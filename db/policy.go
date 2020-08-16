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
	ID       primitive.ObjectID `bson:"_id"`
	Uuid     string             `json:"uuid" bson:"uuid"`
	PolicyId string             `json:"pid" bson:"pid"`
	Version  uint               `json:"version" bson:"version"`
	OPA      string             `json:"policy" bson:"policy"`
}

// This API will add a new policy or update a policy if it already exists
func DBAddPolicy(data *Policy) error {

	if DBFindTenant(data.Uuid) == nil {
		return fmt.Errorf("Cant find tenant %s", data.Uuid)
	}
	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := policyCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"uuid": data.Uuid, "pid": data.PolicyId},
		bson.D{
			{"$set", bson.M{"uuid": data.Uuid, "pid": data.PolicyId, "version": data.Version, "policy": data.OPA}},
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
	err := policyCltn.FindOne(
		context.TODO(),
		bson.M{"uuid": tenant, "pid": policyId},
	).Decode(&policy)
	if err != nil {
		return nil
	}
	return &policy
}
