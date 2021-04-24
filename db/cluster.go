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
var serviceCltn = make(map[string]*mongo.Collection, maxClusters)

func ClusterDBInit(dbClient *mongo.Client) {
	mongoClient = dbClient
	globalClusterDB = dbClient.Database("NxtClusterDB")
	clusterGwCltn = globalClusterDB.Collection("NxtGateways")
	namespaceCltn = globalClusterDB.Collection("NxtNamespaces")
}

func ClusterGetDBName(cl string) string {
	return ("Nxt-" + cl + "-DB")
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
	case "NxtServices":
		_, cok := serviceCltn[cluster]
		if cok == false {
			serviceCltn[cluster] = ClusterDBs[cluster].Collection("NxtServices")
		}
		return serviceCltn[cluster]
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
	serviceCltn[cluster] = cldb.Collection("NxtServices")
}

func ClusterDelDB(cluster string) {
	delete(usersCltn, cluster)
	delete(serviceCltn, cluster)
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
	Version int    `json:"version" bson:"version"`
}

// This API will add a new gateway/cluster
func DBAddClusterGateway(data *Gateway) error {
	version := 1
	gw := DBFindClusterGateway(data.Name)
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
			{"$set", bson.M{"name": data.Name, "version": version}},
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

func DBFindClusterGateway(name string) *ClusterGateway {
	var gateway ClusterGateway
	err := clusterGwCltn.FindOne(
		context.TODO(),
		bson.M{"name": name},
	).Decode(&gateway)
	if err != nil {
		return nil
	}
	return &gateway
}

func DBDelClusterGateway(name string) error {
	_, err := clusterGwCltn.DeleteOne(
		context.TODO(),
		bson.M{"name": name},
	)

	return err
}

// NOTE: The bson decoder will not work if the structure field names dont start with upper case
// Tenant info
type Namespace struct {
	ID      string `json:"_id" bson:"_id"` // Tenant id
	Name    string `json:"name" bson:"name"`
	Image   string `json:"image" bson:"image"`
	Pods    int    `json:"pods" bson:"pods"`
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
				"pods": data.Pods, "version": version}},
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
		msg := fmt.Sprintf("Could not find Clusterusers collection for cluster %s",
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
		err := dbAddClusterSvc(data.Cluster, tenant, s, data.Uid, data.Pod)
		if err != nil {
			return err
		}
	}
	for _, s := range delServices {
		err := dbDelClusterSvc(data.Cluster, tenant, s, data.Uid)
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

// Find all users in a cluster.
func DBFindAllClusterUsers(clid string) []ClusterUser {
	var users []ClusterUser

	clusersCltn := ClusterGetCollection(clid, "NxtUsers")
	if clusersCltn == nil {
		return nil
	}
	// cursor, err := clusersCltn.Find(context.TODO(), bson.M{"tenant": tid})
	cursor, err := clusersCltn.Find(context.TODO(), bson.M{})
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
		err := dbDelClusterSvc(clid, tenant, s, userid)
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
	user := DBFindClusterUser(data.Cluster, tenant, data.Bid)
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
		msg := fmt.Sprintf("Could not find Clusterusers collection for cluster %s",
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
		err := dbAddClusterSvc(data.Cluster, tenant, s, data.Bid, data.Pod)
		if err != nil {
			return err
		}
	}
	for _, s := range delServices {
		err := dbDelClusterSvc(data.Cluster, tenant, s, data.Bid)
		if err != nil {
			return err
		}
	}

	return nil
}

type ClusterService struct {
	Sid     string   `json:"sid" bson:"_id"` // Tenant-ID:Service-ID
	Tenant  string   `json:"tenant" bson:"tenant"`
	Agents  []string `json:"agents" bson:"agents"`
	Pods    []int    `json:"pods" bson:"pods"`
	Version int      `json:"version" bson:"version"`
}

func dbAddClusterSvc(clid string, tenant string, service string, agent string, pod int) error {
	sid := tenant + ":" + service
	version := 1
	svc := DBFindClusterSvc(clid, tenant, service)
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
	clserviceCltn := ClusterGetCollection(clid, "NxtServices")
	if clserviceCltn == nil {
		return nil
	}
	result := clserviceCltn.FindOneAndUpdate(
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

func DBFindClusterSvc(clid string, tenant string, service string) *ClusterService {
	sid := tenant + ":" + service
	var svc ClusterService
	clserviceCltn := ClusterGetCollection(clid, "NxtServices")
	if clserviceCltn == nil {
		return nil
	}
	err := clserviceCltn.FindOne(
		context.TODO(),
		bson.M{"_id": sid},
	).Decode(&svc)
	if err != nil {
		return nil
	}
	return &svc
}

func DBFindAllClusterSvcs(clid string) []ClusterService {
	var svcs []ClusterService

	clserviceCltn := ClusterGetCollection(clid, "NxtServices")
	if clserviceCltn == nil {
		return nil
	}
	cursor, err := clserviceCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &svcs)
	if err != nil {
		return nil
	}

	return svcs
}

func dbDelClusterSvc(clid string, tenant string, service string, agent string) error {
	sid := tenant + ":" + service
	svc := DBFindClusterSvc(clid, tenant, service)
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
	clserviceCltn := ClusterGetCollection(clid, "NxtServices")
	if clserviceCltn == nil {
		return nil // TODO: or return error ?
	}
	if len(agents) == 0 {
		_, err := clserviceCltn.DeleteOne(
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
		result := clserviceCltn.FindOneAndUpdate(
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
