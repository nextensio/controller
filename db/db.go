package db

import (
	"context"
	"log"

	"nextensio/controller/utils"

	"github.com/golang/glog"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

// We open a connection to the DB and keep it around for ever
var dbClient *mongo.Client
var tenantCltn *mongo.Collection
var gatewayCltn *mongo.Collection
var policyCltn *mongo.Collection
var routeCltn *mongo.Collection
var userCltn *mongo.Collection
var userAttrCltn *mongo.Collection
var appCltn *mongo.Collection
var appAttrCltn *mongo.Collection
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
	policyCltn = nxtDB.Collection("NxtPolicies")
	routeCltn = nxtDB.Collection("NxtRoutes")
	userCltn = nxtDB.Collection("NxtUsers")
	userAttrCltn = nxtDB.Collection("NxtUserAttr")
	appCltn = nxtDB.Collection("NxtApps")
	appAttrCltn = nxtDB.Collection("NxtAppAttr")
}

func dbDrop() {
	nxtDB.Drop(context.TODO())
}

func DBReinit() {
	dbConnect()
	ClusterDBInit(dbClient)
	dbDrop()
	dbCollections()
	ClusterDBDrop()
	ClusterDBInit(dbClient)
}

func DBInit() {
	dbConnect()
	dbCollections()
	ClusterDBInit(dbClient)
}

func StrToObjectid(objid string) (primitive.ObjectID, error) {
	return primitive.ObjectIDFromHex(objid)
}
