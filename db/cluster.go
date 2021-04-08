package db

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// DB used by the Nxt Cluster to configure kubernetes rules etc.
var clusterDB *mongo.Database
var clusterGwCltn *mongo.Collection
var namespaceCltn *mongo.Collection
var usersCltn *mongo.Collection
var serviceCltn *mongo.Collection

func ClusterDBInit(dbClient *mongo.Client) {
	clusterDB = dbClient.Database("ClusterDB")
	clusterGwCltn = clusterDB.Collection("NxtGateways")
	namespaceCltn = clusterDB.Collection("NxtNamespaces")
	usersCltn = clusterDB.Collection("NxtUsers")
	serviceCltn = clusterDB.Collection("NxtServices")
}

func ClusterDBDrop() {
	clusterDB.Drop(context.TODO())
}

type ClusterGateway struct {
	Name    string `json:"name" bson:"name"`
	Version int    `json:"version" bson:"version"`
}

// This API will add a new namespace
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
	if err != nil {
		return err.Err()
	}

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
type Namespace struct {
	ID      primitive.ObjectID `json:"_id" bson:"_id"` // Tenant id
	Name    string             `json:"name" bson:"name"`
	Image   string             `json:"image" bson:"image"`
	Pods    int                `json:"pods" bson:"pods"`
	Version int                `json:"version" bson:"version"`
}

// This API will add a new namespace
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
	if err != nil {
		return err.Err()
	}

	return nil
}

func DBFindNamespace(id primitive.ObjectID) *Namespace {
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

func DBDelNamespace(id primitive.ObjectID) error {
	_, err := namespaceCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": id},
	)

	return err
}

type ClusterUser struct {
	Uid       string             `json:"uid" bson:"_id"` // Tenant-ID:[User-ID | Bundle-ID]
	Tenant    primitive.ObjectID `json:"tenant" bson:"tenant"`
	Pod       int                `json:"pod" bson:"pod"`
	Connectid string             `json:"connectid" bson:"connectid"`
	Services  []string           `json:"services" bson:"services"`
	Version   int                `json:"version" bson:"version"`
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

func DBAddClusterUser(tenant primitive.ObjectID, data *User) error {
	uid := tenant.Hex() + ":" + data.Uid
	version := 1
	user := DBFindClusterUser(tenant, data.Uid)
	var addServices []string
	var delServices []string
	if user != nil {
		addServices = diffSlices(data.Services, user.Services)
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
	result := usersCltn.FindOneAndUpdate(
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
		err := dbAddClusterSvc(tenant, s, data.Uid)
		if err != nil {
			return err
		}
	}
	for _, s := range delServices {
		err := dbDelClusterSvc(tenant, s, data.Uid)
		if err != nil {
			return err
		}
	}

	return nil
}

func DBFindClusterUser(tenant primitive.ObjectID, userid string) *ClusterUser {
	uid := tenant.Hex() + ":" + userid
	var user ClusterUser
	err := usersCltn.FindOne(
		context.TODO(),
		bson.M{"_id": uid},
	).Decode(&user)
	if err != nil {
		return nil
	}
	return &user
}

func DBFindAllClusterUsers() []ClusterUser {
	var users []ClusterUser

	cursor, err := usersCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &users)
	if err != nil {
		return nil
	}

	return users
}

func DBDelClusterUser(tenant primitive.ObjectID, userid string) error {
	user := DBFindClusterUser(tenant, userid)
	if user == nil {
		error := fmt.Sprintf("User %s not found", userid)
		return errors.New(error)
	}
	for _, s := range user.Services {
		err := dbDelClusterSvc(tenant, s, userid)
		if err != nil {
			return err
		}
	}
	uid := tenant.Hex() + ":" + userid
	_, err := usersCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": uid},
	)

	return err
}

func DBAddClusterBundle(tenant primitive.ObjectID, data *Bundle) error {
	uid := tenant.Hex() + ":" + data.Bid
	version := 1
	user := DBFindClusterUser(tenant, data.Bid)
	var addServices []string
	var delServices []string
	if user != nil {
		addServices = diffSlices(data.Services, user.Services)
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
	result := usersCltn.FindOneAndUpdate(
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
		err := dbAddClusterSvc(tenant, s, data.Bid)
		if err != nil {
			return err
		}
	}
	for _, s := range delServices {
		err := dbDelClusterSvc(tenant, s, data.Bid)
		if err != nil {
			return err
		}
	}

	return nil
}

type ClusterService struct {
	Sid     string             `json:"sid" bson:"_id"` // Tenant-ID:Service-ID
	Tenant  primitive.ObjectID `json:"tenant" bson:"tenant"`
	Agents  []string           `json:"agents" bson:"agents"`
	Version int                `json:"version" bson:"version"`
}

func dbAddClusterSvc(tenant primitive.ObjectID, service string, agent string) error {
	sid := tenant.Hex() + ":" + service
	version := 1
	svc := DBFindClusterSvc(tenant, service)
	var agents []string
	if svc != nil {
		version = svc.Version + 1
		agents = svc.Agents
	}
	found := false
	for _, v := range agents {
		if v == agent {
			found = true
			break
		}
	}
	if found {
		// no change
		return nil
	} else {
		agents = append(agents, agent)
	}

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	result := serviceCltn.FindOneAndUpdate(
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

	return nil
}

func DBFindClusterSvc(tenant primitive.ObjectID, service string) *ClusterService {
	sid := tenant.Hex() + ":" + service
	var svc ClusterService
	err := serviceCltn.FindOne(
		context.TODO(),
		bson.M{"_id": sid},
	).Decode(&svc)
	if err != nil {
		return nil
	}
	return &svc
}

func DBFindAllClusterSvcs() []ClusterService {
	var svcs []ClusterService

	cursor, err := serviceCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &svcs)
	if err != nil {
		return nil
	}

	return svcs
}

func dbDelClusterSvc(tenant primitive.ObjectID, service string, agent string) error {
	sid := tenant.Hex() + ":" + service
	svc := DBFindClusterSvc(tenant, service)
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
	if len(agents) == 0 {
		_, err := serviceCltn.DeleteOne(
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
		result := serviceCltn.FindOneAndUpdate(
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
