package db

import (
	"context"
	"fmt"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// NOTE: The bson decoder will not work if the structure field names dont start with upper case
type Route struct {
	Route  string             `json:"route" bson:"_id"`
	Tenant primitive.ObjectID `json:"tenant" bson:"tenant"`
	Tag    string             `json:"tag" bson:"tag"`
}

// This API will add a new route or update a route if it already exists
func DBAddRoute(data *Route) error {

	if DBFindTenant(data.Tenant) == nil {
		return fmt.Errorf("Cant find tenant %s", data.Tenant)
	}

	userRoute := strings.Split(data.Route, ":")
	if len(userRoute) != 2 {
		return fmt.Errorf("Route should be in format userid:route")
	}
	if DBFindUser(data.Tenant, userRoute[0]) == nil {
		return fmt.Errorf("Cannot find user %s", userRoute[0])
	}

	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := routeCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Route, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"_id": data.Route, "tenant": data.Tenant, "tag": data.Tag}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindRoute(tenant primitive.ObjectID, routeid string) *Route {
	var route Route
	err := routeCltn.FindOne(
		context.TODO(),
		bson.M{"_id": routeid, "tenant": tenant},
	).Decode(&route)
	if err != nil {
		return nil
	}
	return &route
}

func DBFindAllRoutes(tenant primitive.ObjectID) []Route {
	var routes []Route

	cursor, err := routeCltn.Find(context.TODO(), bson.M{"tenant": tenant})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &routes)
	if err != nil {
		return nil
	}

	return routes
}

func DBDelRoute(tenant primitive.ObjectID, routeid string) error {
	_, err := routeCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": routeid, "tenant": tenant},
	)

	return err
}
