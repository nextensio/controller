package db

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// NOTE: The bson decoder will not work if the structure field names dont start with upper case
type Tenant struct {
	ID       primitive.ObjectID `bson:"_id"`
	Uuid     string             `json:"uuid" bson:"uuid"`
	Idp      string             `json:"idp" bson:"idp"`
	Gateways []string           `json:"gateways" bson:"gateways"`
}

// This API will add a new tenant or update a tenant if it already exists
func DBAddTenant(data *Tenant) error {

	for i := 0; i < len(data.Gateways); i++ {
		if DBFindGateway(data.Gateways[i]) == nil {
			return fmt.Errorf("Gateway %s not configured", data.Gateways[i])
		}
	}

	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := tenantCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"uuid": data.Uuid},
		bson.D{
			{"$set", bson.M{"uuid": data.Uuid, "idp": data.Idp, "gateways": data.Gateways}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindTenant(uuid string) *Tenant {
	var tenant Tenant
	err := tenantCltn.FindOne(
		context.TODO(),
		bson.M{"uuid": uuid},
	).Decode(&tenant)
	if err != nil {
		return nil
	}
	return &tenant
}

// This API will add a new gateway or update a gateway if it already exists
func DBAddGateway(data *Gateway) error {

	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := gatewayCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"name": data.Name},
		bson.D{
			{"$set", bson.M{"name": data.Name, "zone": data.Zone}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

type Gateway struct {
	ID   primitive.ObjectID `bson:"_id"`
	Name string             `json:"name" bson:"name"`
	Zone string             `json:"zone" bson:"zone"`
}

func DBFindGateway(name string) *Gateway {
	var gateway Gateway
	err := gatewayCltn.FindOne(
		context.TODO(),
		bson.M{"name": name},
	).Decode(&gateway)
	if err != nil {
		return nil
	}
	return &gateway
}

type User struct {
	ID       primitive.ObjectID `bson:"_id"`
	Tenant   string             `json:"tenant" bson:"tenant"`
	Userid   string             `json:"userid" bson:"userid"`
	Username string             `json:"name" bson:"name"`
	Email    string             `json:"email" bson:"email"`
}

// This API will add a new gateway or update a gateway if it already exists
func DBAddUser(data *User) error {

	if DBFindTenant(data.Tenant) == nil {
		return fmt.Errorf("Unknown tenant")
	}

	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := userCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"userid": data.Userid, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"userid": data.Userid, "tenant": data.Tenant, "name": data.Username, "email": data.Email}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindUser(tenant string, userid string) *User {
	var user User
	err := userCltn.FindOne(
		context.TODO(),
		bson.M{"userid": userid, "tenant": tenant},
	).Decode(&user)
	if err != nil {
		return nil
	}
	return &user
}

type UserAttr struct {
	Id       primitive.ObjectID `bson:"_id"`
	Userid   string             `bson:"userid" json:"userid"`
	Tenant   string             `bson:"tenant" json:"tenant"`
	Majver   string             `bson:"majver" json:"maj_ver"`
	Minver   string             `bson:"minver" json:"min_ver"`
	Category string             `bson:"category" json:"category"`
	Type     string             `bson:"type" json:"type"`
	Level    string             `bson:"level" json:"level"`
	Dept     []string           `bson:"dept" json:"dept"`
	Team     []string           `bson:"team" json:"team"`
}

// This API will add a new gateway or update a gateway if it already exists
func DBAddUserAttr(data *UserAttr) error {

	if DBFindUser(data.Tenant, data.Userid) == nil {
		return fmt.Errorf("Cannot find user")
	}

	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := userAttrCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"userid": data.Userid, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"userid": data.Userid, "tenant": data.Tenant, "majver": data.Majver,
				"minver": data.Minver, "category": data.Category, "type": data.Type, "level": data.Level,
				"dept": data.Dept, "team": data.Team}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindUserAttr(tenant string, userid string) *UserAttr {
	var user UserAttr
	err := userAttrCltn.FindOne(
		context.TODO(),
		bson.M{"userid": userid, "tenant": tenant},
	).Decode(&user)
	if err != nil {
		return nil
	}
	return &user
}

type Bundle struct {
	ID         primitive.ObjectID `bson:"_id"`
	Tenant     string             `json:"tenant" bson:"tenant"`
	Bid        string             `json:"bid" bson:"bid"`
	Bundlename string             `json:"name" bson:"name"`
}

// This API will add a new gateway or update a gateway if it already exists
func DBAddBundle(data *Bundle) error {

	if DBFindTenant(data.Tenant) == nil {
		return fmt.Errorf("Unknown tenant")
	}

	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := appCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"bid": data.Bid, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"bid": data.Bid, "tenant": data.Tenant, "name": data.Bundlename}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindBundle(tenant string, bundleid string) *Bundle {
	var app Bundle
	err := appCltn.FindOne(
		context.TODO(),
		bson.M{"bid": bundleid, "tenant": tenant},
	).Decode(&app)
	if err != nil {
		return nil
	}
	return &app
}

type BundleAttr struct {
	Id          primitive.ObjectID `bson:"_id"`
	Bid         string             `bson:"bid" json:"bid"`
	Tenant      string             `bson:"tenant" json:"tenant"`
	Majver      string             `bson:"majver" json:"maj_ver"`
	Minver      string             `bson:"minver" json:"min_ver"`
	Team        []string           `bson:"team" json:"team"`
	Dept        []string           `bson:"dept" json:"dept"`
	Contrib     string             `bson:"IC" json:"IC"`
	Manager     string             `bson:"manager" json:"manager"`
	Nonemployee string             `bson:"nonemployee" json:"nonemployee"`
}

// This API will add a new gateway or update a gateway if it already exists
func DBAddBundleAttr(data *BundleAttr) error {

	if DBFindBundle(data.Tenant, data.Bid) == nil {
		return fmt.Errorf("Cannot find user")
	}

	// The upsert option asks the DB to add a tenant if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := appAttrCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"bid": data.Bid, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"bid": data.Bid, "tenant": data.Tenant, "majver": data.Majver,
				"minver": data.Minver, "team": data.Team, "dept": data.Dept,
				"IC": data.Contrib, "manager": data.Manager, "nonemployee": data.Nonemployee}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindBundleAttr(tenant string, bundleid string) *BundleAttr {
	var app BundleAttr
	err := appAttrCltn.FindOne(
		context.TODO(),
		bson.M{"bid": bundleid, "tenant": tenant},
	).Decode(&app)
	if err != nil {
		return nil
	}
	return &app
}
