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

const maxTenants = 1000
const nxtOurDB = "NxtDB"

var nxtMongoVer int

// We open a connection to the DB and keep it around for ever
var dbClient *mongo.Client

var tenantCltn *mongo.Collection
var certCltn *mongo.Collection
var gatewayCltn *mongo.Collection

var nxtDB *mongo.Database
var tenantDBs = make(map[string]*mongo.Database, maxTenants) 

var tenantPolicyCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantUserCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantUserAttrCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantAppCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantAppAttrCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantHostAttrCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantRouteCltn = make(map[string]*mongo.Collection, maxTenants)

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
	return true
}

func dbGetTenantDBName(tenant string) string {
	if nxtMongoVer < 1 {
		return nxtOurDB
	}
	return ("Nxt-" + tenant + "-DB")
}

func dbCollections() {
	nxtDB = dbClient.Database(nxtOurDB)
	tenantCltn = nxtDB.Collection("NxtTenants")
	certCltn = nxtDB.Collection("NxtCerts")
	gatewayCltn = nxtDB.Collection("NxtGateways")

	// The collections below need to be in per-tenant DBs
	// The DBs can be known only when tenants are created/known
	// If nxtMongoVer < 1, we don't support per-tenant DBs, so
	// initialize the tenant collections now, else return.
	if nxtMongoVer >= 1 {
		return  // per-tenant collections supported
	}
	tenantDBs[nxtOurDB] = nxtDB
	tenantPolicyCltn[nxtOurDB] = tenantDBs[nxtOurDB].Collection("NxtPolicies")
	tenantRouteCltn[nxtOurDB] = tenantDBs[nxtOurDB].Collection("NxtRoutes")
	tenantUserCltn[nxtOurDB] = tenantDBs[nxtOurDB].Collection("NxtUsers")
	tenantUserAttrCltn[nxtOurDB] = tenantDBs[nxtOurDB].Collection("NxtUserAttr")
	tenantAppCltn[nxtOurDB] = tenantDBs[nxtOurDB].Collection("NxtApps")
	tenantAppAttrCltn[nxtOurDB] = tenantDBs[nxtOurDB].Collection("NxtAppAttr")
	tenantHostAttrCltn[nxtOurDB] = tenantDBs[nxtOurDB].Collection("NxtHostAttr")
}

func dbGetCollection(tnt primitive.ObjectID, cltn string) *mongo.Collection {
	tenant := tnt.Hex()
	if nxtMongoVer < 1 {
		tenant = nxtOurDB  // per-tenant DB not supported
	}
	_, ok := tenantDBs[tenant]
	if ok == false {
		tenantDBs[tenant] = dbClient.Database(dbGetTenantDBName(tenant))
	}
	switch cltn {
	case "NxtPolicies":
		_, cok := tenantPolicyCltn[tenant]
		if cok == false {
			tenantPolicyCltn[tenant] = tenantDBs[tenant].Collection("NxtPolicies")
		}
		return tenantPolicyCltn[tenant]
	case "NxtUsers":
		_, cok := tenantUserCltn[tenant]
		if cok == false {
			tenantUserCltn[tenant] = tenantDBs[tenant].Collection("NxtUsers")
		}
		return tenantUserCltn[tenant]
	case "NxtUserAttr":
		_, cok := tenantUserAttrCltn[tenant]
		if cok == false {
			tenantUserAttrCltn[tenant] = tenantDBs[tenant].Collection("NxtUserAttr")
		}
		return tenantUserAttrCltn[tenant]
	case "NxtApps":
		_, cok := tenantAppCltn[tenant]
		if cok == false {
			tenantAppCltn[tenant] = tenantDBs[tenant].Collection("NxtApps")
		}
		return tenantAppCltn[tenant]
	case "NxtAppAttr":
		_, cok := tenantAppAttrCltn[tenant]
		if cok == false {
			tenantAppAttrCltn[tenant] = tenantDBs[tenant].Collection("NxtAppAttr")
		}
		return tenantAppAttrCltn[tenant]
	case "NxtRoutes":
		_, cok := tenantRouteCltn[tenant]
		if cok == false {
			tenantRouteCltn[tenant] = tenantDBs[tenant].Collection("NxtRoutes")
		}
		return tenantRouteCltn[tenant]
	case "NxtHostAttr":
		_, cok := tenantHostAttrCltn[tenant]
		if cok == false {
			tenantHostAttrCltn[tenant] = tenantDBs[tenant].Collection("NxtHostAttr")
		}
		return tenantHostAttrCltn[tenant]
	}
	return nil
}

func dbAddTenantDB(tnt primitive.ObjectID) {
	tenant := tnt.Hex()
	if nxtMongoVer < 1 {
		tenant = nxtOurDB  // per-tenant DB not supported
	}
	_, ok := tenantDBs[tenant]
	if ok {
		return
	}
	tenantDBs[tenant] = dbClient.Database(dbGetTenantDBName(tenant))
	dbAddTenantCollections(tenant, tenantDBs[tenant])
}

func dbAddTenantCollections(tenant string, tntdb *mongo.Database) {
	tenantPolicyCltn[tenant] = tntdb.Collection("NxtPolicies")
	tenantUserCltn[tenant] = tntdb.Collection("NxtUsers")
	tenantUserAttrCltn[tenant] = tntdb.Collection("NxtUserAttr")
	tenantAppCltn[tenant] = tntdb.Collection("NxtApps")
	tenantAppAttrCltn[tenant] = tntdb.Collection("NxtAppAttr")
	tenantRouteCltn[tenant] = tntdb.Collection("NxtRoutes")
	tenantHostAttrCltn[tenant] = tntdb.Collection("NxtHostAttr")
}

func dbDelTenantDB(tnt primitive.ObjectID) {
	if nxtMongoVer < 1 {
		return  // per-tenant DB not supported
	}
	tenant := tnt.Hex()
	delete(tenantPolicyCltn, tenant)
	delete(tenantUserCltn, tenant)
	delete(tenantUserAttrCltn, tenant)
	delete(tenantAppCltn, tenant)
	delete(tenantAppAttrCltn, tenant)
	delete(tenantRouteCltn, tenant)
	delete(tenantHostAttrCltn, tenant)
	tenantDBs[tenant].Drop(context.TODO())
	delete(tenantDBs, tenant)
	
}

func dbDrop() {
	if nxtMongoVer >= 1 {  // per-tenant DBs supported
		dbTenants := DBFindAllTenants()
		for i := 0; i < len(dbTenants); i++ {
			tdb := dbClient.Database(dbGetTenantDBName(dbTenants[i].ID.Hex()))
			tdb.Drop(context.TODO())
		}
	}
	nxtDB.Drop(context.TODO())
	ClusterDBDrop()
}

func DBReinit() {
	// For automated tests using golang "testing" package.
	// Open a client and reconnect to mongoDB server.
	// Open NxtDB, ClusterDB and any tenant DBs and drop/nuke them from mongoDB.
	// Open fresh databases for NxtDB and ClusterDB and open our collections within
	// them. If separate tenant DBs are not supported, then open the tenant
	// collections within NxtDB. If separate tenant DBs are supported, a tenant
	// DB will be created when a tenant is added. The collections in that database
	// will be opened at that time.
	DBInit()
	dbDrop()
	dbSetup()
}

func DBInit() {
	nxtMongoVer = utils.GetEnvInt("NXT_MONGO_IMPL_VER", 0)
	for dbConnect() != true {
		time.Sleep(1 * time.Second)
	}
	dbSetup()
}

func dbSetup() {
	dbCollections()
	ClusterDBInit(dbClient)
}

func StrToObjectid(objid string) (primitive.ObjectID, error) {
	return primitive.ObjectIDFromHex(objid)
}
