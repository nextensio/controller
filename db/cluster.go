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
var clusterCfgCltn *mongo.Collection

var usersCltn = make(map[string]*mongo.Collection, maxClusters)
var bundleCltn = make(map[string]*mongo.Collection, maxClusters)

func ClusterDBInit(dbClient *mongo.Client) {
	mongoClient = dbClient
	globalClusterDB = dbClient.Database("NxtClusterDB")
	clusterGwCltn = globalClusterDB.Collection("NxtGateways")
	namespaceCltn = globalClusterDB.Collection("NxtNamespaces")
	clusterCfgCltn = globalClusterDB.Collection("NxtClusters")
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
	case "NxtUsers":
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

func ClusterDBDrop() {
	allGws := DBFindAllGateways()
	for i := 0; i < len(allGws); i++ {
		Cluster := DBGetClusterName(allGws[i].Name)
		cldb := mongoClient.Database(ClusterGetDBName(Cluster))
		cldb.Drop(context.TODO())
	}
	globalClusterDB.Drop(context.TODO())
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
	clc := DBFindClusterConfig(Cluster, tenant)
	if clc != nil {
		// If ClusterConfig exists, use following fields
		version = clc.Version + 1
	}
	id := Cluster + ":" + tenant

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := clusterCfgCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": id},
		bson.D{
			{"$set", bson.M{"_id": id,
				"apodsets": data.ApodSets, "apodrepl": data.ApodRepl,
				"image":   data.Image,
				"cluster": Cluster, "tenant": tenant, "version": version}},
		},
		&opt,
	)
	if err.Err() != nil {
		glog.Errorf("Add ClusterConfig failed - %v", err.Err())
		return err.Err()
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
func DBFindClusterConfig(clid string, tenant string) *ClusterConfig {
	var clcfg ClusterConfig
	id := clid + ":" + tenant
	err := clusterCfgCltn.FindOne(context.TODO(), bson.M{"_id": id}).Decode(&clcfg)
	if err != nil {
		return nil
	}
	return &clcfg
}

// Check if any tenants are present in a cluster - return tenant count
// 0 == no tenants; > 0 indicates tenants present
func DBAnyTenantsInCluster(clid string) int {
	clcfg := DBFindAllTenantsInCluster(clid)
	if clcfg == nil {
		return 0
	}
	return len(clcfg)
}

// Find and return docs for all tenants present in a cluster
func DBFindAllTenantsInCluster(clid string) []ClusterConfig {
	var clcfg []ClusterConfig
	cursor, err := clusterCfgCltn.Find(context.TODO(), bson.M{"cluster": clid})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &clcfg)
	if err != nil {
		return nil
	}
	if len(clcfg) > 0 {
		return clcfg
	}
	return nil
}

// Find and return docs for all clusters for specified tenant
func DBFindAllClustersForTenant(tenant string) []ClusterConfig {
	var clcfg []ClusterConfig
	cursor, err := clusterCfgCltn.Find(context.TODO(), bson.M{"tenant": tenant})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &clcfg)
	if err != nil {
		return nil
	}
	if len(clcfg) > 0 {
		return clcfg
	}
	return nil
}

// Delete the ClusterConfig doc for a tenant within a cluster.
// For now, check if there are any active users or connectors.
// If none, then delete the ClusterConfig.
// Need a way to ensure that new users are blocked from connecting
// to any of the tenant's pods that are to be removed.
func DBDelClusterConfig(clid string, tenant string) error {
	clcfg := DBFindClusterConfig(clid, tenant)
	if clcfg == nil {
		return nil
	}
	bundles := DBFindAllClusterBundlesForTenant(clid, tenant)
	if bundles != nil {
		for _, b := range bundles {
			_ = DBDelOneClusterBundle(clid, b.Uid)
		}
	}
	// TODO: removal of pods

	id := clid + ":" + tenant
	_, err := clusterCfgCltn.DeleteOne(context.TODO(), bson.M{"_id": id})
	glog.Infof("ClusterConfig deleted for %s", id)

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

// TODO: This API adds the bundle to ALL gateways as of now, but a tenant
// might not have all gateways given to it, it might have a subset of all
// gateways. When that support comes in later, modify this to ensure the bundle
// is added only to the tenant's subset. And even in the tenant's gateway subset,
// all gateways might not need this bundle pre-configured. We will eventually move
// to a model where when the bundle onboards with controller before connecting to
// a gateway, the controller will tell the gateway to add the configs for the
// bundle. Which also means that when the gateway has no connections from the
// bundle for a long period of time (idle time), "somehow" the bundle yamls
// should get removed from the gateway. Will implement that one day and then we
// dont need to do this busines of adding configs to all gateways
func DBAddClusterBundle(tenant string, data *Bundle) error {
	cls := DBFindAllClustersForTenant(tenant)
	for _, cl := range cls {
		err := DBAddOneClusterBundle(tenant, data, cl.Cluster)
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
	cls := DBFindAllClustersForTenant(tenant)
	for _, cl := range cls {
		err := DBDelOneClusterBundle(cl.Cluster, tenant+":"+bundleid)
		if err != nil {
			return err
		}
	}
	return nil
}
