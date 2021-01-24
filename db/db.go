package db

import (
	"context"
	"nextensio/controller/utils"
	"time"

	"github.com/golang/glog"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

// We open a connection to the DB and keep it around for ever
var dbClient *mongo.Client
var tenantCltn *mongo.Collection
var certCltn *mongo.Collection
var gatewayCltn *mongo.Collection
var policyCltn *mongo.Collection
var routeCltn *mongo.Collection
var userCltn *mongo.Collection
var userAttrCltn *mongo.Collection
var appCltn *mongo.Collection
var appAttrCltn *mongo.Collection
var hostAttrCltn *mongo.Collection
var nxtDB *mongo.Database

func dbConnect() bool {
	mongoURI := utils.GetEnv("MONGO_URI", "mongodb://127.0.0.1:27017/")
	var err error

	if dbClient != nil {
		dbClient.Disconnect(context.TODO())
		dbClient = nil
	}
	dbClient, err = mongo.NewClient(options.Client().ApplyURI(mongoURI))
	if err != nil {
		glog.Error(err)
		return false
	}

	err = dbClient.Connect(context.TODO())
	if err != nil {
		glog.Error("Failed Database Init")
		return false
	}
	err = dbClient.Ping(context.TODO(), readpref.Primary())
	if err != nil {
		glog.Error(err)
		return false

	}
	nxtDB = dbClient.Database("NxtDB")
	return true
}

func dbCollections() {
	tenantCltn = nxtDB.Collection("NxtTenants")
	certCltn = nxtDB.Collection("NxtCerts")
	gatewayCltn = nxtDB.Collection("NxtGateways")
	policyCltn = nxtDB.Collection("NxtPolicies")
	routeCltn = nxtDB.Collection("NxtRoutes")
	userCltn = nxtDB.Collection("NxtUsers")
	userAttrCltn = nxtDB.Collection("NxtUserAttr")
	appCltn = nxtDB.Collection("NxtApps")
	appAttrCltn = nxtDB.Collection("NxtAppAttr")
	hostAttrCltn = nxtDB.Collection("NxtHostAttr")
}

func dbDrop() {
	nxtDB.Drop(context.TODO())
}

func DBReinit() {
	for dbConnect() != true {
		time.Sleep(1 * time.Second)
	}
	ClusterDBInit(dbClient)
	dbDrop()
	dbCollections()
	ClusterDBDrop()
	ClusterDBInit(dbClient)
}

func DBInit() {
	for dbConnect() != true {
		time.Sleep(1 * time.Second)
	}
	dbCollections()
	ClusterDBInit(dbClient)
}

func StrToObjectid(objid string) (primitive.ObjectID, error) {
	return primitive.ObjectIDFromHex(objid)
}
