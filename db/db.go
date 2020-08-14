package db

import (
	"context"
	"fmt"
	"log"

	"nextensio/controller/utils"

	"github.com/golang/glog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

// We open a connection to the DB and keep it around for ever
var dbClient *mongo.Client
var tenantCltn *mongo.Collection
var gatewayCltn *mongo.Collection
var nxtDB *mongo.Database

func dbConnect() {
	mongoURI := utils.GetEnv("MONGO_URI", "mongodb://127.0.0.1:27017/")
	var err error
	dbClient, err = mongo.NewClient(options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal(err)
	}

	err = dbClient.Connect(context.TODO())
	if err != nil {
		glog.Fatal("Failed Database Init")
		return
	}
	err = dbClient.Ping(context.TODO(), readpref.Primary())
	if err != nil {
		glog.Fatal(err)
		return
	}
	nxtDB = dbClient.Database("NxtDB")
}

func dbCollections() {
	tenantCltn = nxtDB.Collection("NxtTenants")
	gatewayCltn = nxtDB.Collection("NxtGateways")
}

func dbDrop() {
	nxtDB.Drop(context.TODO())
}

func DBReinit() {
	dbConnect()
	dbDrop()
	dbCollections()
}

func DBInit() {
	dbConnect()
	dbCollections()
}

// NOTE: The bson decoder will not work if the structure field names dont start with upper case
type Tenant struct {
	ID       primitive.ObjectID `json:"_id" bson:"_id"`
	Uuid     string             `json:"uuid" bson:"uuid"`
	Idp      string             `json:"idp" bson:"idp"`
	Gateways []string           `json:"gateways" bson:"gateways"`
}

// This API will add a new tenant or update a tenant if it already exists
func DBAddTenant(data *Tenant) error {

	for i := 0; i < len(data.Gateways); i++ {
		if DBFindGateway(data.Gateways[i]) == nil {
			return fmt.Errorf("Gateway %s not configured", data.Gateways[i])
		}
	}

	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := tenantCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"uuid": data.Uuid},
		bson.D{
			{"$set", bson.M{"uuid": data.Uuid, "idp": data.Idp, "gateways": data.Gateways}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindTenant(uuid string) *Tenant {
	var tenant Tenant
	err := tenantCltn.FindOne(
		context.TODO(),
		bson.M{"uuid": uuid},
	).Decode(&tenant)
	if err != nil {
		return nil
	}
	return &tenant
}

// This API will add a new gateway or update a gateway if it already exists
func DBAddGateway(data *Gateway) error {

	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := gatewayCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"name": data.Name},
		bson.D{
			{"$set", bson.M{"name": data.Name, "zone": data.Zone}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

type Gateway struct {
	ID   primitive.ObjectID `json:"_id" bson:"_id"`
	Name string             `json:"name" bson:"name"`
	Zone string             `json:"zone" bson:"zone"`
}

func DBFindGateway(name string) *Gateway {
	var gateway Gateway
	err := gatewayCltn.FindOne(
		context.TODO(),
		bson.M{"name": name},
	).Decode(&gateway)
	if err != nil {
		return nil
	}
	return &gateway
}
