package main

import (
	"context"
	"nextensio/controller/db"
)

func dbDrop() {
	// Purge the cluster related operational data first before removing
	// gateway/cluster configuration
	for {
		err := db.ClusterDBDrop()
		if err == nil {
			break
		}
	}
	for {
		dbTenants, err := db.DBFindAllTenants()
		for i := 0; i < len(dbTenants); i++ {
			tdb := db.DBClient.Database(db.DBGetTenantDBName(dbTenants[i].ID))
			tdb.Drop(context.TODO())
		}
		if err == nil {
			break
		}
	}
	db.NxtDB.Drop(context.TODO())
}

func dbReinit() {
	// For automated tests using golang "testing" package.
	// Open a client and reconnect to mongoDB server.
	// Open NxtDB, ClusterDB and any tenant DBs and drop/nuke them from mongoDB.
	// Open fresh databases for NxtDB and ClusterDB and open our collections within
	// them. If separate tenant DBs are not supported, then open the tenant
	// collections within NxtDB. If separate tenant DBs are supported, a tenant
	// DB will be created when a tenant is added. The collections in that database
	// will be opened at that time.
	db.DBInit()
	dbDrop()
	db.DBSetup()
}

func main() {
}
