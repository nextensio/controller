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
var userviceCltn = make(map[string]*mongo.Collection, maxClusters)
var bserviceCltn = make(map[string]*mongo.Collection, maxClusters)

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

func ClusterGetPodName(pod int, podtype string) string {
	prefix := "apod"
	if podtype != "A" {
		prefix = "cpod"
	}
	return prefix + fmt.Sprintf("%d", pod)
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
	case "NxtUServices":
		_, cok := userviceCltn[cluster]
		if cok == false {
			userviceCltn[cluster] = ClusterDBs[cluster].Collection("NxtUServices")
		}
		return userviceCltn[cluster]
	case "NxtBServices":
		_, cok := bserviceCltn[cluster]
		if cok == false {
			bserviceCltn[cluster] = ClusterDBs[cluster].Collection("NxtBServices")
		}
		return bserviceCltn[cluster]
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
	userviceCltn[cluster] = cldb.Collection("NxtUServices")
	bserviceCltn[cluster] = cldb.Collection("NxtBServices")
}

func ClusterDelDB(cluster string) {
	delete(usersCltn, cluster)
	delete(bundleCltn, cluster)
	delete(userviceCltn, cluster)
	delete(bserviceCltn, cluster)
	ClusterDBs[cluster].Drop(context.TODO())
	delete(ClusterDBs, cluster)
}

func ClusterDBDrop() {
	allGws := DBFindAllGateways()
	for i := 0; i < len(allGws); i++ {
		cldb := mongoClient.Database(ClusterGetDBName(allGws[i].Cluster))
		cldb.Drop(context.TODO())
	}
	globalClusterDB.Drop(context.TODO())
}

type ClusterGateway struct {
	Name    string `json:"name" bson:"name"`
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
	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := clusterGwCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"name": data.Name},
		bson.D{
			{"$set", bson.M{"name": data.Name, "cluster": data.Cluster,
				"version": version}},
		},
		&opt,
	)
	if err.Err() != nil {
		return err.Err()
	}

	// Create the logical DB for the cluster specific collections that are
	// required by the nextensio manager in each cluster.
	ClusterAddDB(data.Cluster)

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
		bson.M{"name": gwname},
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
		bson.M{"name": gwname},
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
	Image   string `json:"image" bson:"image"`
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
			{"$set", bson.M{"name": data.Name, "image": data.Image,
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
	Apods    int    `json:"apods" bson:"apods"`
	Cpods    int    `json:"cpods" bson:"cpods"`
	NextApod int    `json:"nextapod" bson:"nextapod"`
	NextCpod int    `json:"nextcpod" bson:"nextcpod"`
	Version  int    `json:"version" bson:"version"`
}

// This API will add a new doc or update one for pods allocated to a tenant
// within a specific cluster
func DBAddClusterConfig(tenant string, data *TenantCluster) error {
	version := 1
	nextapod := 0
	nextcpod := 0
	clc := DBFindClusterConfig(data.Cluster, tenant)
	if clc != nil {
		// If ClusterConfig exists, use following fields
		version = clc.Version + 1
		nextapod = clc.NextApod
		nextcpod = clc.NextCpod
	}
	id := data.Cluster + ":" + tenant

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
			{"$set", bson.M{"_id": id, "nextapod": nextapod, "nextcpod": nextcpod,
				"apods": data.Apods, "cpods": data.Cpods, "image": data.Image,
				"cluster": data.Cluster, "tenant": tenant, "version": version}},
		},
		&opt,
	)
	if err.Err() != nil {
		glog.Errorf("Add ClusterConfig failed - %v", err.Err())
		return err.Err()
	}

	// TODO: Handle increase or decrease in # of pods

	return nil
}

// Update the doc for a tenant within a cluster when a pod is assigned to a user.
// Note that we don't bump up Version.
func DBUpdClusterConfig(clcfg *ClusterConfig) error {

	change := bson.M{"nextapod": clcfg.NextApod, "nextcpod": clcfg.NextCpod}
	filter := bson.D{{"_id", clcfg.Id}}
	update := bson.D{{"$set", change}}
	_, err := clusterCfgCltn.UpdateOne(context.TODO(), filter, update)
	return err
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
		msg := fmt.Sprintf("Could not find ClusterConfig to delete for %s:%s", clid, tenant)
		glog.Errorf(msg)
		return errors.New(msg)
	}
	users := DBFindAllClusterUsersForTenant(clid, tenant)
	if users != nil {
		msg := fmt.Sprintf("Cannot delete ClusterConfig for %s:%s - active users",
			clid, tenant)
		glog.Errorf(msg)
		return errors.New(msg)
	}
	bundles := DBFindAllClusterBundlesForTenant(clid, tenant)
	if bundles != nil {
		msg := fmt.Sprintf("Cannot delete ClusterConfig for %s:%s - active connectors",
			clid, tenant)
		glog.Errorf(msg)
		return errors.New(msg)
	}
	// TODO: removal of pods

	id := clid + ":" + tenant
	_, err := clusterCfgCltn.DeleteOne(context.TODO(), bson.M{"_id": id})
	glog.Infof("ClusterConfig deleted for %s", id)

	return err
}

// To be used when we support dynamic assignment of cluster and pod to a user or
// cluster to a connector. The algorithm here may need to be enhanced considering the
// requirement to take pods offline, either for an upgrade or for reducing number of pods.
// It is ok to allow a user to connect to the same pod from multiple devices.
// Multi-homing of a user from the same device is TBD.
// Multi-homing of connectors will always be to different pods, either within the
// same cluster or different clusters.
func ClusterUserGetNextPod(tenant string, clid string, utype string) int {
	nextpod := 0

	clcfg := DBFindClusterConfig(clid, tenant)
	if clcfg == nil {
		return nextpod
	}
	switch utype {
	case "agent":
		if clcfg.Apods == 0 {
			return 0
		}
		nextpod = clcfg.NextApod + 1 // Pods are created one-based
		clcfg.NextApod = (nextpod + 1) % clcfg.Apods
	case "connector":
		if clcfg.Cpods == 0 {
			return 0
		}
		nextpod = clcfg.NextCpod + 1 // Pods are created one-based
		clcfg.NextCpod = (nextpod + 1) % clcfg.Cpods
	default:
		return 0
	}

	// Update NextPod in cluster config doc
	DBUpdClusterConfig(clcfg)

	return nextpod
}

// Common structure for agent or connector
type ClusterUser struct {
	Uid       string   `json:"uid" bson:"_id"` // Tenant-ID:[User-ID | Bundle-ID]
	Tenant    string   `json:"tenant" bson:"tenant"`
	Pod       int      `json:"pod" bson:"pod"`
	Connectid string   `json:"connectid" bson:"connectid"`
	Services  []string `json:"services" bson:"services"`
	Version   int      `json:"version" bson:"version"`
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

// Today, this function is called when a new user is added to the system.
// At that time, we are also assigning the user to a cluster and pod.
// In future, the cluster/pod assignment will be dynamic when user signs-in.
// Also, same user may connect via multiple devices, to the same or different
// pods.
func DBAddClusterUser(tenant string, data *User) error {
	uid := tenant + ":" + data.Uid
	version := 1
	user := DBFindClusterUser(data.Cluster, tenant, data.Uid)
	var addServices []string
	var delServices []string
	if user != nil {
		// If pod chnaged, all the services also are considered modified
		if data.Pod != user.Pod {
			addServices = data.Services
		} else {
			addServices = diffSlices(data.Services, user.Services)
		}
		delServices = diffSlices(user.Services, data.Services)
		version = user.Version + 1
	} else {
		addServices = data.Services
	}
	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	clusersCltn := ClusterGetCollection(data.Cluster, "NxtUsers")
	if clusersCltn == nil {
		msg := fmt.Sprintf("Could not find users collection for cluster %s",
			data.Cluster)
		glog.Error(msg)
		return errors.New(msg)
	}
	result := clusersCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": uid},
		bson.D{
			{"$set", bson.M{"tenant": tenant, "version": version, "pod": data.Pod,
				"connectid": data.Connectid, "services": data.Services}},
		},
		&opt,
	)
	if result.Err() != nil {
		return result.Err()
	}

	for _, s := range addServices {
		err := DBAddUserClusterSvc(data.Cluster, tenant, s, data.Uid, data.Pod)
		if err != nil {
			return err
		}
	}
	for _, s := range delServices {
		err := DBDelUserClusterSvc(data.Cluster, tenant, s, data.Uid)
		if err != nil {
			return err
		}
	}

	return nil
}

// Find a specific tenant's user within a cluster
func DBFindClusterUser(clid string, tenant string, userid string) *ClusterUser {
	uid := tenant + ":" + userid
	var user ClusterUser
	clusersCltn := ClusterGetCollection(clid, "NxtUsers")
	if clusersCltn == nil {
		return nil
	}
	err := clusersCltn.FindOne(
		context.TODO(),
		bson.M{"_id": uid},
	).Decode(&user)
	if err != nil {
		return nil
	}
	return &user
}

func DBFindAllClusterUsersForTenant(clid string, tenant string) []ClusterUser {
	var users []ClusterUser

	clusersCltn := ClusterGetCollection(clid, "NxtUsers")
	if clusersCltn == nil {
		return nil
	}
	cursor, err := clusersCltn.Find(context.TODO(), bson.M{"tenant": tenant})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &users)
	if err != nil {
		return nil
	}

	return users
}

func DBDelClusterUser(clid string, tenant string, userid string) error {
	user := DBFindClusterUser(clid, tenant, userid)
	if user == nil {
		error := fmt.Sprintf("User %s not found", userid)
		return errors.New(error)
	}
	for _, s := range user.Services {
		err := DBDelUserClusterSvc(clid, tenant, s, userid)
		if err != nil {
			return err
		}
	}
	clusersCltn := ClusterGetCollection(clid, "NxtUsers")
	if clusersCltn == nil {
		msg := fmt.Sprintf("Could not find Clusterusers collection for cluster %s", clid)
		glog.Error(msg)
		return errors.New(msg)
	}
	uid := tenant + ":" + userid
	_, err := clusersCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": uid},
	)

	return err
}

// Today, this function is called when a new connector is added to the system.
// At that time, we are also assigning the connector to a cluster and pod.
// TBD whether cluster assignment should be dynamic when connector signs-in
// as connectors are static. Pod assignment may also be dynamic and done by k8s
// if we have to assign from a replicaset.
// We also need to cater to multi-homing of connectors to different pods.
func DBAddClusterBundle(tenant string, data *Bundle) error {
	uid := tenant + ":" + data.Bid
	version := 1
	user := DBFindClusterBundle(data.Cluster, tenant, data.Bid)
	var addServices []string
	var delServices []string
	if user != nil {
		// If pod chnaged, all the services also are considered modified
		if data.Pod != user.Pod {
			addServices = data.Services
		} else {
			addServices = diffSlices(data.Services, user.Services)
		}
		delServices = diffSlices(user.Services, data.Services)
		version = user.Version + 1
	} else {
		addServices = data.Services
	}
	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	clbundleCltn := ClusterGetCollection(data.Cluster, "NxtConnectors")
	if clbundleCltn == nil {
		msg := fmt.Sprintf("Could not find Connectors collection for cluster %s",
			data.Cluster)
		glog.Error(msg)
		return errors.New(msg)
	}
	result := clbundleCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": uid},
		bson.D{
			{"$set", bson.M{"tenant": tenant, "version": version, "pod": data.Pod,
				"connectid": data.Connectid, "services": data.Services}},
		},
		&opt,
	)
	if result.Err() != nil {
		return result.Err()
	}

	for _, s := range addServices {
		err := DBAddBundleClusterSvc(data.Cluster, tenant, s, data.Bid, data.Pod)
		if err != nil {
			return err
		}
	}
	for _, s := range delServices {
		err := DBDelBundleClusterSvc(data.Cluster, tenant, s, data.Bid)
		if err != nil {
			return err
		}
	}

	return nil
}

// Find a specific tenant's connector within a cluster
func DBFindClusterBundle(clid string, tenant string, bundleid string) *ClusterUser {
	uid := tenant + ":" + bundleid
	var user ClusterUser
	clbundleCltn := ClusterGetCollection(clid, "NxtConnectors")
	if clbundleCltn == nil {
		return nil
	}
	err := clbundleCltn.FindOne(
		context.TODO(),
		bson.M{"_id": uid},
	).Decode(&user)
	if err != nil {
		return nil
	}
	return &user
}

func DBFindAllClusterBundlesForTenant(clid string, tenant string) []ClusterUser {
	var users []ClusterUser

	clbundleCltn := ClusterGetCollection(clid, "NxtConnectors")
	if clbundleCltn == nil {
		return nil
	}
	cursor, err := clbundleCltn.Find(context.TODO(), bson.M{"tenant": tenant})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &users)
	if err != nil {
		return nil
	}

	return users
}

func DBDelClusterBundle(clid string, tenant string, bundleid string) error {
	user := DBFindClusterBundle(clid, tenant, bundleid)
	if user == nil {
		error := fmt.Sprintf("Connector %s not found", bundleid)
		return errors.New(error)
	}
	for _, s := range user.Services {
		err := DBDelBundleClusterSvc(clid, tenant, s, bundleid)
		if err != nil {
			return err
		}
	}
	clbundleCltn := ClusterGetCollection(clid, "NxtConnectors")
	if clbundleCltn == nil {
		msg := fmt.Sprintf("Could not find connectors collection for cluster %s", clid)
		glog.Error(msg)
		return errors.New(msg)
	}
	uid := tenant + ":" + bundleid
	_, err := clbundleCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": uid},
	)

	return err
}

type ClusterService struct {
	Sid     string   `json:"sid" bson:"_id"` // Tenant-ID:Service-ID
	Tenant  string   `json:"tenant" bson:"tenant"`
	Agents  []string `json:"agents" bson:"agents"`
	Pods    []int    `json:"pods" bson:"pods"`
	Version int      `json:"version" bson:"version"`
}

func DBAddUserClusterSvc(clid string, tenant string, service string, agent string, pod int) error {
	sid := tenant + ":" + service
	version := 1
	svc := DBFindUserClusterSvc(clid, tenant, service)
	var agents []string
	var pods []int
	if svc != nil {
		version = svc.Version + 1
		agents = svc.Agents
		pods = svc.Pods
	}
	nochange := false
	found := false
	for i, v := range agents {
		if v == agent {
			found = true
			if pods[i] == pod {
				nochange = true
				break
			} else {
				pods[i] = pod
			}
		}
	}
	if nochange {
		// no change
		return nil
	}
	if !found {
		agents = append(agents, agent)
		pods = append(pods, pod)
	}

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	cluserviceCltn := ClusterGetCollection(clid, "NxtUServices")
	if cluserviceCltn == nil {
		return nil
	}
	result := cluserviceCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": sid},
		bson.D{
			{"$set", bson.M{"tenant": tenant, "agents": agents, "pods": pods, "version": version}},
		},
		&opt,
	)
	if result.Err() != nil {
		return result.Err()
	}

	return nil
}

// Find a specific tenant user service within a cluster
func DBFindUserClusterSvc(clid string, tenant string, service string) *ClusterService {
	sid := tenant + ":" + service
	var svc ClusterService
	cluserviceCltn := ClusterGetCollection(clid, "NxtUServices")
	if cluserviceCltn == nil {
		return nil
	}
	err := cluserviceCltn.FindOne(
		context.TODO(),
		bson.M{"_id": sid},
	).Decode(&svc)
	if err != nil {
		return nil
	}
	return &svc
}

// Find all user services within a cluster for a specific tenant
func DBFindAllUserClusterSvcsForTenant(clid string, tenant string) []ClusterService {
	var svcs []ClusterService

	cluserviceCltn := ClusterGetCollection(clid, "NxtUServices")
	if cluserviceCltn == nil {
		return nil
	}
	cursor, err := cluserviceCltn.Find(context.TODO(), bson.M{"tenant": tenant})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &svcs)
	if err != nil {
		return nil
	}

	return svcs
}

func DBDelUserClusterSvc(clid string, tenant string, service string, agent string) error {
	sid := tenant + ":" + service
	svc := DBFindUserClusterSvc(clid, tenant, service)
	if svc == nil {
		return errors.New("No service")
	}
	agents := svc.Agents
	found := false
	for i, v := range agents {
		if v == agent {
			agents = append(agents[:i], agents[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		// no change
		return nil
	}
	version := svc.Version + 1
	cluserviceCltn := ClusterGetCollection(clid, "NxtUServices")
	if cluserviceCltn == nil {
		return nil // TODO: or return error ?
	}
	if len(agents) == 0 {
		_, err := cluserviceCltn.DeleteOne(
			context.TODO(),
			bson.M{"_id": sid},
		)
		if err != nil {
			return err
		}
	} else {
		// The upsert option asks the DB to add if one is not found
		upsert := true
		after := options.After
		opt := options.FindOneAndUpdateOptions{
			ReturnDocument: &after,
			Upsert:         &upsert,
		}
		result := cluserviceCltn.FindOneAndUpdate(
			context.TODO(),
			bson.M{"_id": sid},
			bson.D{
				{"$set", bson.M{"tenant": tenant, "agents": agents, "version": version}},
			},
			&opt,
		)
		if result.Err() != nil {
			return result.Err()
		}
	}
	return nil
}

func DBAddBundleClusterSvc(clid string, tenant string, service string, agent string, pod int) error {
	sid := tenant + ":" + service
	version := 1
	svc := DBFindBundleClusterSvc(clid, tenant, service)
	var agents []string
	var pods []int
	if svc != nil {
		version = svc.Version + 1
		agents = svc.Agents
		pods = svc.Pods
	}
	nochange := false
	found := false
	for i, v := range agents {
		if v == agent {
			found = true
			if pods[i] == pod {
				nochange = true
				break
			} else {
				pods[i] = pod
			}
		}
	}
	if nochange {
		// no change
		return nil
	}
	if !found {
		agents = append(agents, agent)
		pods = append(pods, pod)
	}

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	clbserviceCltn := ClusterGetCollection(clid, "NxtBServices")
	if clbserviceCltn == nil {
		return nil
	}
	result := clbserviceCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": sid},
		bson.D{
			{"$set", bson.M{"tenant": tenant, "agents": agents, "pods": pods, "version": version}},
		},
		&opt,
	)
	if result.Err() != nil {
		return result.Err()
	}

	return nil
}

// Find a specific tenant connector service within a cluster
func DBFindBundleClusterSvc(clid string, tenant string, service string) *ClusterService {
	sid := tenant + ":" + service
	var svc ClusterService
	clbserviceCltn := ClusterGetCollection(clid, "NxtBServices")
	if clbserviceCltn == nil {
		return nil
	}
	err := clbserviceCltn.FindOne(
		context.TODO(),
		bson.M{"_id": sid},
	).Decode(&svc)
	if err != nil {
		return nil
	}
	return &svc
}

// Find all connector services within a cluster for a specific tenant
func DBFindAllBundleClusterSvcsForTenant(clid string, tenant string) []ClusterService {
	var svcs []ClusterService

	clbserviceCltn := ClusterGetCollection(clid, "NxtBServices")
	if clbserviceCltn == nil {
		return nil
	}
	cursor, err := clbserviceCltn.Find(context.TODO(), bson.M{"tenant": tenant})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &svcs)
	if err != nil {
		return nil
	}

	return svcs
}

func DBDelBundleClusterSvc(clid string, tenant string, service string, agent string) error {
	sid := tenant + ":" + service
	svc := DBFindBundleClusterSvc(clid, tenant, service)
	if svc == nil {
		return errors.New("No service")
	}
	agents := svc.Agents
	found := false
	for i, v := range agents {
		if v == agent {
			agents = append(agents[:i], agents[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		// no change
		return nil
	}
	version := svc.Version + 1
	clbserviceCltn := ClusterGetCollection(clid, "NxtBServices")
	if clbserviceCltn == nil {
		return nil // TODO: or return error ?
	}
	if len(agents) == 0 {
		_, err := clbserviceCltn.DeleteOne(
			context.TODO(),
			bson.M{"_id": sid},
		)
		if err != nil {
			return err
		}
	} else {
		// The upsert option asks the DB to add if one is not found
		upsert := true
		after := options.After
		opt := options.FindOneAndUpdateOptions{
			ReturnDocument: &after,
			Upsert:         &upsert,
		}
		result := clbserviceCltn.FindOneAndUpdate(
			context.TODO(),
			bson.M{"_id": sid},
			bson.D{
				{"$set", bson.M{"tenant": tenant, "agents": agents, "version": version}},
			},
			&opt,
		)
		if result.Err() != nil {
			return result.Err()
		}
	}
	return nil
}
