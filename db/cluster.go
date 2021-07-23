package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang/glog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const maxClusters = 100 // A swag

// These collections represent operational data needed to configure
// the kubernetes system. They are populated from configuration data
// as well as dynamically at run-time when agents connect or leave.
// We will organize the collections as follows for scaling nextensio
// manager (mel) processing to configure the kubernetes system.
// The NxtClusters and NxtNamespaces collections will be in a single
// DB called NxtClusterDB since we need a global view of all clusters
// and tenants.
// The NxtUsers and NxtServices collections will be in per-cluster DBs
// so that the nextensio manager in each cluster can work with the
// operational data relevant to just that cluster.

var mongoClient *mongo.Client
var globalClusterDB *mongo.Database
var ClusterDBs = make(map[string]*mongo.Database, maxClusters)

var clusterGwCltn *mongo.Collection
var namespaceCltn *mongo.Collection

var usersCltn = make(map[string]*mongo.Collection, maxClusters)
var bundleCltn = make(map[string]*mongo.Collection, maxClusters)

func ClusterDBInit(dbClient *mongo.Client) {
	mongoClient = dbClient
	globalClusterDB = dbClient.Database("NxtClusterDB")
	clusterGwCltn = globalClusterDB.Collection("NxtGateways")
	namespaceCltn = globalClusterDB.Collection("NxtNamespaces")
}

func ClusterGetDBName(cl string) string {
	return ("Nxt-" + cl + "-DB")
}

func ClusterGetApodSetName(tenant string, pod int) string {
	return tenant + "-apod" + fmt.Sprintf("%d", pod)
}

func ClusterGetCollection(cluster string, cltn string) *mongo.Collection {

	_, ok := ClusterDBs[cluster]
	if ok == false {
		ClusterDBs[cluster] = mongoClient.Database(ClusterGetDBName(cluster))
	}
	switch cltn {
	case "NxtTenants":
		_, cok := usersCltn[cluster]
		if cok == false {
			usersCltn[cluster] = ClusterDBs[cluster].Collection("NxtUsers")
		}
		return usersCltn[cluster]
	case "NxtConnectors":
		_, cok := bundleCltn[cluster]
		if cok == false {
			bundleCltn[cluster] = ClusterDBs[cluster].Collection("NxtConnectors")
		}
		return bundleCltn[cluster]
	}
	return nil
}

func ClusterAddDB(cluster string) {

	_, ok := ClusterDBs[cluster]
	if ok {
		return
	}
	ClusterDBs[cluster] = mongoClient.Database(ClusterGetDBName(cluster))
	ClusterAddCollections(cluster, ClusterDBs[cluster])
}

func ClusterAddCollections(cluster string, cldb *mongo.Database) {
	usersCltn[cluster] = cldb.Collection("NxtUsers")
	bundleCltn[cluster] = cldb.Collection("NxtConnectors")
}

func ClusterDelDB(cluster string) {
	delete(usersCltn, cluster)
	delete(bundleCltn, cluster)
	ClusterDBs[cluster].Drop(context.TODO())
	delete(ClusterDBs, cluster)
}

func ClusterDBDrop() error {
	err, allGws := DBFindAllGateways()
	if err != nil {
		return err
	}
	for i := 0; i < len(allGws); i++ {
		Cluster := DBGetClusterName(allGws[i].Name)
		cldb := mongoClient.Database(ClusterGetDBName(Cluster))
		cldb.Drop(context.TODO())
	}
	globalClusterDB.Drop(context.TODO())

	return nil
}

type ClusterGateway struct {
	Name    string `json:"name" bson:"_id"`
	Cluster string `json:"cluster" bson:"cluster"`
	Version int    `json:"version" bson:"version"`
}

// This API will add a new gateway/cluster
func DBAddClusterGateway(data *Gateway) error {
	version := 1
	// Get the gateway/cluster doc using the gateway name
	gw := DBFindGatewayCluster(data.Name)
	if gw != nil {
		version = gw.Version + 1
	}
	Cluster := DBGetClusterName(data.Name)
	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := clusterGwCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Name},
		bson.D{
			{"$set", bson.M{"cluster": Cluster, "version": version}},
		},
		&opt,
	)
	if err.Err() != nil {
		return err.Err()
	}

	// Create the logical DB for the cluster specific collections that are
	// required by the nextensio manager in each cluster.
	ClusterAddDB(Cluster)

	return nil
}

// Find gateway/cluster doc given the cluster name
func DBFindClusterGateway(clname string) *ClusterGateway {
	var gateway ClusterGateway
	err := clusterGwCltn.FindOne(
		context.TODO(),
		bson.M{"cluster": clname},
	).Decode(&gateway)
	if err != nil {
		return nil
	}
	return &gateway
}

// Find gateway/cluster doc given the gateway name
func DBFindGatewayCluster(gwname string) *ClusterGateway {
	var gateway ClusterGateway
	err := clusterGwCltn.FindOne(
		context.TODO(),
		bson.M{"_id": gwname},
	).Decode(&gateway)
	if err != nil {
		return nil
	}
	return &gateway
}

func DBDelClusterGateway(gwname string) error {
	clgw := DBFindGatewayCluster(gwname)
	if clgw == nil {
		return errors.New("Cluster gateway not found - cannot delete")
	}
	_, err := clusterGwCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": gwname},
	)
	if err != nil {
		return err
	}

	// Remove the logical DB for per-cluster collections
	ClusterDelDB(clgw.Cluster)
	return nil
}

// NOTE: The bson decoder will not work if the structure field names dont start with upper case
// Tenant info
type Namespace struct {
	ID      string `json:"_id" bson:"_id"` // Tenant id
	Name    string `json:"name" bson:"name"`
	Version int    `json:"version" bson:"version"`
}

// This API will add a new namespace or update an existing one
func DBAddNamespace(data *Tenant) error {

	version := 1
	nspc := DBFindNamespace(data.ID)
	if nspc != nil {
		version = nspc.Version + 1
	}
	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := namespaceCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.ID},
		bson.D{
			{"$set", bson.M{"name": data.Name,
				"version": version}},
		},
		&opt,
	)
	if err.Err() != nil {
		return err.Err()
	}

	return nil
}

func DBFindNamespace(id string) *Namespace {
	var namespace Namespace
	err := namespaceCltn.FindOne(
		context.TODO(),
		bson.M{"_id": id},
	).Decode(&namespace)
	if err != nil {
		return nil
	}
	return &namespace
}

func DBFindAllNamespaces() []Namespace {
	var namespaces []Namespace

	cursor, err := namespaceCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &namespaces)
	if err != nil {
		return nil
	}

	return namespaces
}

func DBDelNamespace(id string) error {
	_, err := namespaceCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": id},
	)

	return err
}

// Each cluster will have one or more tenants, and for each tenant, we will configure
// how many pods should be deployed in that cluster and what image should be used.
// TODO very soon: separation of apods from cpods.
// The mongoDB collection with this doc will be created from the TenantCluster configs
// and give the overall composition of a cluster by various tenants.
// Dynamic pod assignment for each user will also be managed from here.
// Changes in Image should trigger a regeneration of the deployment yamls in the
// associated cluster by its clustermgr.
// Changes in number of pods will also trigger adds or deletes so that new pods can be
// deployed or existing ones brought down.
// Currently, we don't support increasing or decreasing pods once allocated.
// TODO: addition and removal of pods for any tenant in any cluster.
// The cluster manager in each cluster generates a connectivity mesh between clusters
// from this collection to create egress gateways as needed.
// TODO: Processing of tenant removals from a cluster (and egress gateway removals).
type ClusterConfig struct {
	Id       string `json:"id" bson:"_id"` // ClusterID:TenantID
	Cluster  string `json:"cluster" bson:"cluster"`
	Tenant   string `json:"tenant" bson:"tenant"`
	Image    string `json:"image" bson:"image"`
	ApodRepl int    `json:"apodrepl" bson:"apodrepl"`
	ApodSets int    `json:"apodsets" bson:"apodsets"`
	Version  int    `json:"version" bson:"version"`
}

// This API will add a new doc or update one for pods allocated to a tenant
// within a specific cluster
func DBAddClusterConfig(tenant string, data *TenantCluster) error {
	version := 1
	Cluster := DBGetClusterName(data.Gateway)
	err, clc := DBFindClusterConfig(Cluster, tenant)
	if err != nil {
		return err
	}
	if clc != nil {
		// If ClusterConfig exists, use following fields
		version = clc.Version + 1
	}

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	cltenantCltn := ClusterGetCollection(Cluster, "NxtTenants")
	if cltenantCltn == nil {
		msg := fmt.Sprintf("Could not find tenant collection for cluster %s",
			Cluster)
		glog.Error(msg)
		return errors.New(msg)
	}
	result := cltenantCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": tenant},
		bson.D{
			{"$set", bson.M{"_id": tenant,
				"apodsets": data.ApodSets, "apodrepl": data.ApodRepl,
				"image":   data.Image,
				"cluster": Cluster, "tenant": tenant, "version": version}},
		},
		&opt,
	)
	if result.Err() != nil {
		glog.Errorf("Add ClusterConfig failed - %v", result.Err())
		return err
	}

	// The very first time we are associating a gateway with a tenant,
	// add all the bundles of the tenant to this gateway
	if clc == nil {
		bundles := DBFindAllBundlesStruct(tenant)
		for _, b := range bundles {
			e := DBAddOneClusterBundle(tenant, &b, Cluster)
			if e != nil {
				return e
			}
		}
	}

	return nil
}

// Find the ClusterConfig doc for a tenant within a cluster
func DBFindClusterConfig(clid string, tenant string) (error, *ClusterConfig) {
	var clcfg ClusterConfig
	cltenantCltn := ClusterGetCollection(clid, "NxtTenants")
	if cltenantCltn == nil {
		msg := fmt.Sprintf("Could not find tenant collection for cluster %s",
			clid)
		glog.Error(msg)
		return errors.New(msg), nil
	}
	err := cltenantCltn.FindOne(context.TODO(), bson.M{"_id": tenant}).Decode(&clcfg)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return err, nil
	}
	return nil, &clcfg
}

// Check if any tenants are present in a cluster - return tenant count
// 0 == no tenants; > 0 indicates tenants present
func DBAnyTenantsInCluster(clid string) (error, bool) {
	cltenantCltn := ClusterGetCollection(clid, "NxtTenants")
	if cltenantCltn == nil {
		msg := fmt.Sprintf("Could not find tenant collection for cluster %s",
			clid)
		glog.Error(msg)
		return errors.New(msg), false
	}
	cursor, err := cltenantCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return err, false
	}
	defer cursor.Close(context.TODO())
	for cursor.Next(context.TODO()) {
		return nil, true
	}

	return nil, false
}

// Delete the ClusterConfig doc for a tenant within a cluster.
func DBDelClusterConfig(clid string, tenant string) error {
	err, clcfg := DBFindClusterConfig(clid, tenant)
	if err != nil {
		return err
	}
	if clcfg == nil {
		return nil
	}
	bundles := DBFindAllClusterBundlesForTenant(clid, tenant)
	if bundles != nil {
		for _, b := range bundles {
			_ = DBDelOneClusterBundle(clid, b.Uid)
		}
	}

	cltenantCltn := ClusterGetCollection(clid, "NxtTenants")
	if cltenantCltn == nil {
		msg := fmt.Sprintf("Could not find tenant collection for cluster %s",
			clid)
		glog.Error(msg)
		return errors.New(msg)
	}
	_, err = cltenantCltn.DeleteOne(context.TODO(), bson.M{"_id": tenant})
	glog.Infof("ClusterConfig deleted for %s", clid, tenant)

	return err
}

func diffSlices(a []string, b []string) []string {
	var new []string
	var found = false
	for _, c := range a {
		found = false
		for _, d := range b {
			if c == d {
				found = true
				break
			}
		}
		if !found {
			new = append(new, c)
		}
	}

	return new
}

// The Pod here indicates the "pod set" that this user should
// connect to, each pod set has its own number of replicas etc..
type ClusterBundle struct {
	Uid       string   `json:"uid" bson:"_id"`
	Tenant    string   `json:"tenant" bson:"tenant"`
	Pod       string   `json:"pod" bson:"pod"`
	Connectid string   `json:"connectid" bson:"connectid"`
	Services  []string `json:"services" bson:"services"`
	Version   int      `json:"version" bson:"version"`
	CpodRepl  int      `json:"cpodrepl" bson:"cpodrepl"`
}

func DBAddOneClusterBundle(tenant string, data *Bundle, Cluster string) error {
	uid := tenant + ":" + data.Bid
	version := 1
	bundle := DBFindClusterBundle(Cluster, uid)
	if bundle != nil {
		version = bundle.Version + 1
	}
	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	clbundleCltn := ClusterGetCollection(Cluster, "NxtConnectors")
	if clbundleCltn == nil {
		msg := fmt.Sprintf("Could not find Connectors collection for cluster %s",
			Cluster)
		glog.Error(msg)
		return errors.New(msg)
	}
	result := clbundleCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": uid},
		bson.D{
			{"$set", bson.M{"tenant": tenant, "version": version, "pod": data.Pod,
				"connectid": data.Connectid, "services": data.Services, "cpodrepl": data.CpodRepl}},
		},
		&opt,
	)
	if result.Err() != nil {
		return result.Err()
	}

	return nil
}

func DBAddClusterBundle(tenant string, data *Bundle) error {
	err, gws := DBFindAllGatewaysForTenant(tenant)
	if err != nil {
		return err
	}
	for _, gw := range gws {
		err := DBAddOneClusterBundle(tenant, data, DBGetClusterName(gw.Name))
		if err != nil {
			return err
		}
	}
	return nil
}

// Find a specific tenant's connector within a cluster
func DBFindClusterBundle(clid string, tidbid string) *ClusterBundle {
	var bundle ClusterBundle
	clbundleCltn := ClusterGetCollection(clid, "NxtConnectors")
	if clbundleCltn == nil {
		return nil
	}
	err := clbundleCltn.FindOne(
		context.TODO(),
		bson.M{"_id": tidbid},
	).Decode(&bundle)
	if err != nil {
		return nil
	}
	return &bundle
}

func DBFindAllClusterBundlesForTenant(clid string, tenant string) []ClusterBundle {
	var bundles []ClusterBundle

	clbundleCltn := ClusterGetCollection(clid, "NxtConnectors")
	if clbundleCltn == nil {
		return nil
	}
	cursor, err := clbundleCltn.Find(context.TODO(), bson.M{"tenant": tenant})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &bundles)
	if err != nil {
		return nil
	}

	return bundles
}

func DBDelOneClusterBundle(clid string, tidbid string) error {
	bundle := DBFindClusterBundle(clid, tidbid)
	if bundle == nil {
		error := fmt.Sprintf("Connector %s not found", tidbid)
		return errors.New(error)
	}
	clbundleCltn := ClusterGetCollection(clid, "NxtConnectors")
	if clbundleCltn == nil {
		msg := fmt.Sprintf("Could not find connectors collection for cluster %s", clid)
		glog.Error(msg)
		return errors.New(msg)
	}
	_, err := clbundleCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": tidbid},
	)

	return err
}

func DBDelClusterBundle(tenant string, bundleid string) error {
	err, gws := DBFindAllGatewaysForTenant(tenant)
	if err != nil {
		return err
	}
	for _, gw := range gws {
		err := DBDelOneClusterBundle(DBGetClusterName(gw.Name), tenant+":"+bundleid)
		if err != nil {
			return err
		}
	}
	return nil
}
