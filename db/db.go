package db

import (
	"context"
	"flag"
	"nextensio/controller/utils"
	"time"

	"github.com/golang/glog"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

const maxTenants = 1000

// We open a connection to the DB and keep it around for ever
var dbClient *mongo.Client

var tenantCltn *mongo.Collection
var certCltn *mongo.Collection
var gatewayCltn *mongo.Collection

var nxtDB *mongo.Database
var tenantDBs = make(map[string]*mongo.Database, maxTenants)

var tenantClusCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantPolicyCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantUserCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantUserAttrCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantAttrSetCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantAppCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantAppAttrCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantHostAttrCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantRouteCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantOnboardCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantTraceReqCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantBundleRulesCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantHostRulesCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantTraceReqRulesCltn = make(map[string]*mongo.Collection, maxTenants)
var tenantStatsRulesCltn = make(map[string]*mongo.Collection, maxTenants)

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
	return ("Nxt-" + tenant + "-DB")
}

func dbCollections() {
	nxtDB = dbClient.Database("NxtDB")
	tenantCltn = nxtDB.Collection("NxtTenants")
	certCltn = nxtDB.Collection("NxtCerts")
	gatewayCltn = nxtDB.Collection("NxtGateways")
}

func dbGetCollection(tnt string, cltn string) *mongo.Collection {
	tenant := tnt
	_, ok := tenantDBs[tenant]
	if ok == false {
		tenantDBs[tenant] = dbClient.Database(dbGetTenantDBName(tenant))
	}
	switch cltn {
	case "NxtTenantClusters":
		_, cok := tenantClusCltn[tenant]
		if cok == false {
			tenantClusCltn[tenant] = tenantDBs[tenant].Collection("NxtTenantClusters")
		}
		return tenantClusCltn[tenant]
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
	case "NxtAttrSet":
		_, cok := tenantAttrSetCltn[tenant]
		if cok == false {
			tenantAttrSetCltn[tenant] = tenantDBs[tenant].Collection("NxtAttrSet")
		}
		return tenantAttrSetCltn[tenant]
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
	case "NxtOnboardLog":
		_, cok := tenantOnboardCltn[tenant]
		if cok == false {
			tenantOnboardCltn[tenant] = tenantDBs[tenant].Collection("NxtOnboardLog")
		}
		return tenantOnboardCltn[tenant]
	case "NxtTraceRequests":
		_, cok := tenantTraceReqCltn[tenant]
		if cok == false {
			tenantTraceReqCltn[tenant] = tenantDBs[tenant].Collection("NxtTraceRequests")
		}
		return tenantTraceReqCltn[tenant]
	case "NxtBundleRules":
		_, cok := tenantBundleRulesCltn[tenant]
		if cok == false {
			tenantBundleRulesCltn[tenant] = tenantDBs[tenant].Collection("NxtBundleRules")
		}
		return tenantBundleRulesCltn[tenant]
	case "NxtHostRules":
		_, cok := tenantHostRulesCltn[tenant]
		if cok == false {
			tenantHostRulesCltn[tenant] = tenantDBs[tenant].Collection("NxtHostRules")
		}
		return tenantHostRulesCltn[tenant]
	case "NxtTraceReqRules":
		_, cok := tenantTraceReqRulesCltn[tenant]
		if cok == false {
			tenantTraceReqRulesCltn[tenant] = tenantDBs[tenant].Collection("NxtTraceReqRules")
		}
		return tenantTraceReqRulesCltn[tenant]
	case "NxtStatsRule":
		_, cok := tenantStatsRulesCltn[tenant]
		if cok == false {
			tenantStatsRulesCltn[tenant] = tenantDBs[tenant].Collection("NxtStatsRule")
		}
		return tenantStatsRulesCltn[tenant]
	}
	return nil
}

func dbAddTenantDB(tnt string) {
	tenant := tnt
	_, ok := tenantDBs[tenant]
	if ok {
		return
	}
	tenantDBs[tenant] = dbClient.Database(dbGetTenantDBName(tenant))
	dbAddTenantCollections(tenant, tenantDBs[tenant])
}

func dbAddTenantCollections(tenant string, tntdb *mongo.Database) {
	tenantClusCltn[tenant] = tntdb.Collection("NxtTenantClusters")
	tenantPolicyCltn[tenant] = tntdb.Collection("NxtPolicies")
	tenantUserCltn[tenant] = tntdb.Collection("NxtUsers")
	tenantUserAttrCltn[tenant] = tntdb.Collection("NxtUserAttr")
	tenantAttrSetCltn[tenant] = tntdb.Collection("NxtAttrSet")
	tenantAppCltn[tenant] = tntdb.Collection("NxtApps")
	tenantAppAttrCltn[tenant] = tntdb.Collection("NxtAppAttr")
	tenantRouteCltn[tenant] = tntdb.Collection("NxtRoutes")
	tenantHostAttrCltn[tenant] = tntdb.Collection("NxtHostAttr")
	tenantOnboardCltn[tenant] = tntdb.Collection("NxtOnboardLog")
	tenantTraceReqCltn[tenant] = tntdb.Collection("NxtTraceRequests")
	tenantBundleRulesCltn[tenant] = tntdb.Collection("NxtBundleRules")
	tenantHostRulesCltn[tenant] = tntdb.Collection("NxtHostRules")
	tenantTraceReqRulesCltn[tenant] = tntdb.Collection("NxtTraceReqRules")
	tenantStatsRulesCltn[tenant] = tntdb.Collection("NxtStatsRule")
}

func dbDelTenantDB(tnt string) {
	tenant := tnt
	delete(tenantClusCltn, tenant)
	delete(tenantPolicyCltn, tenant)
	delete(tenantUserCltn, tenant)
	delete(tenantUserAttrCltn, tenant)
	delete(tenantAttrSetCltn, tenant)
	delete(tenantAppCltn, tenant)
	delete(tenantAppAttrCltn, tenant)
	delete(tenantRouteCltn, tenant)
	delete(tenantHostAttrCltn, tenant)
	delete(tenantOnboardCltn, tenant)
	delete(tenantTraceReqCltn, tenant)
	delete(tenantBundleRulesCltn, tenant)
	delete(tenantHostRulesCltn, tenant)
	delete(tenantTraceReqRulesCltn, tenant)
	delete(tenantStatsRulesCltn, tenant)
	tenantDBs[tenant].Drop(context.TODO())
	delete(tenantDBs, tenant)

}

func dbDrop() {
	// Purge the cluster related operational data first before removing
	// gateway/cluster configuration
	for {
		err := ClusterDBDrop()
		if err == nil {
			break
		}
	}
	dbTenants := DBFindAllTenants()
	for i := 0; i < len(dbTenants); i++ {
		tdb := dbClient.Database(dbGetTenantDBName(dbTenants[i].ID))
		tdb.Drop(context.TODO())
	}
	nxtDB.Drop(context.TODO())
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
	flag.Parse()
	for dbConnect() != true {
		time.Sleep(1 * time.Second)
	}
	dbSetup()
}

func dbSetup() {
	dbCollections()
	ClusterDBInit(dbClient)
}
