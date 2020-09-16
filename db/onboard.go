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
	ID       primitive.ObjectID `json:"_id" bson:"_id"`
	Name     string             `json:"name" bson:"name"`
	Gateways []string           `json:"gateways" bson:"gateways"`
}

// This API will add a new tenant or update a tenant if it already exists
func DBAddTenant(data *Tenant) error {

	for i := 0; i < len(data.Gateways); i++ {
		if DBFindGateway(data.Gateways[i]) == nil {
			return fmt.Errorf("Gateway %s not configured", data.Gateways[i])
		}
	}

	_, err := tenantCltn.InsertOne(
		context.TODO(),
		bson.M{"name": data.Name, "gateways": data.Gateways},
	)

	if err != nil {
		return err
	}
	return nil
}

func DBFindTenant(id primitive.ObjectID) *Tenant {
	var tenant Tenant
	err := tenantCltn.FindOne(
		context.TODO(),
		bson.M{"_id": id},
	).Decode(&tenant)
	if err != nil {
		return nil
	}
	return &tenant
}

func DBFindAllTenants() []Tenant {
	var tenants []Tenant

	cursor, err := tenantCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &tenants)
	if err != nil {
		return nil
	}

	return tenants
}

func DBDelTenant(id primitive.ObjectID) error {
	_, err := tenantCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": id},
	)

	return err
}

type Gateway struct {
	Name   string `json:"name" bson:"_id"`
	IPAddr string `json:"ipaddr" bson:"ipaddr"`
}

// This API will add a new gateway or update a gateway if it already exists
func DBAddGateway(data *Gateway) error {

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := gatewayCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Name},
		bson.D{
			{"$set", bson.M{"_id": data.Name, "ipaddr": data.IPAddr}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindGateway(name string) *Gateway {
	var gateway Gateway
	err := gatewayCltn.FindOne(
		context.TODO(),
		bson.M{"_id": name},
	).Decode(&gateway)
	if err != nil {
		return nil
	}
	return &gateway
}

func DBFindAllGateways() []Gateway {
	var gateways []Gateway

	cursor, err := gatewayCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &gateways)
	if err != nil {
		return nil
	}

	return gateways
}

type User struct {
	Uid      string             `json:"uid" bson:"_id"`
	Tenant   primitive.ObjectID `json:"tenant" bson:"tenant"`
	Username string             `json:"name" bson:"name"`
	Email    string             `json:"email" bson:"email"`
}

// This API will add/update a new user
func DBAddUser(data *User) error {

	if DBFindTenant(data.Tenant) == nil {
		return fmt.Errorf("Unknown tenant")
	}

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := userCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Uid, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"_id": data.Uid, "tenant": data.Tenant, "name": data.Username, "email": data.Email}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindUser(tenant primitive.ObjectID, userid string) *User {
	var user User
	err := userCltn.FindOne(
		context.TODO(),
		bson.M{"_id": userid, "tenant": tenant},
	).Decode(&user)
	if err != nil {
		return nil
	}
	return &user
}

func DBFindAllUsers(tenant primitive.ObjectID) []User {
	var users []User

	cursor, err := userCltn.Find(context.TODO(), bson.M{"tenant": tenant})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &users)
	if err != nil {
		return nil
	}

	return users
}

func DBDelUser(tenant primitive.ObjectID, userid string) error {
	_, err := userCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": userid, "tenant": tenant},
	)
	return err
}

type DataHdr struct {
	ID     string             `bson:"_id" json:"ID"`
	Majver string             `bson:"majver" json:"majver"`
	Minver string             `bson:"minver" json:"minver"`
	Tenant primitive.ObjectID `bson:"tenant" json:"tenant"`
}

// This API will add/update a user Attribute Header
func DBAddUserAttrHdr(data *DataHdr) error {

	// The upsert option asks the DB to add  if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := userAttrCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": "UserAttr", "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"_id": "UserAttr", "tenant": data.Tenant, "minver": data.Minver, "majver": data.Majver}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindUserAttrHdr(tenant primitive.ObjectID) *DataHdr {
	var attr DataHdr
	err := userAttrCltn.FindOne(
		context.TODO(),
		bson.M{"_id": "UserAttr", "tenant": tenant},
	).Decode(&attr)
	if err != nil {
		return nil
	}
	return &attr
}

func DBDelUserAttrHdr(tenant primitive.ObjectID) error {
	_, err := userAttrCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": "UserAttr", "tenant": tenant},
	)

	return err
}

type UserAttr struct {
	Uid      string             `bson:"_id" json:"uid"`
	Tenant   primitive.ObjectID `bson:"tenant" json:"tenant"`
	Category string             `bson:"category" json:"category"`
	Type     string             `bson:"type" json:"type"`
	Level    string             `bson:"level" json:"level"`
	Dept     []string           `bson:"dept" json:"dept"`
	Team     []string           `bson:"team" json:"team"`
}

// This API will add a new/update user attributes
func DBAddUserAttr(data *UserAttr) error {

	if DBFindUser(data.Tenant, data.Uid) == nil {
		return fmt.Errorf("Cannot find user")
	}

	// TODO: These versions have to be incremented
	hdr := DataHdr{Majver: "1", Minver: "0", Tenant: data.Tenant}
	DBAddUserAttrHdr(&hdr)

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := userAttrCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Uid, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"_id": data.Uid, "tenant": data.Tenant, "category": data.Category,
				"type": data.Type, "level": data.Level, "dept": data.Dept, "team": data.Team}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindUserAttr(tenant primitive.ObjectID, userid string) *UserAttr {
	var user UserAttr
	err := userAttrCltn.FindOne(
		context.TODO(),
		bson.M{"_id": userid, "tenant": tenant},
	).Decode(&user)
	if err != nil {
		return nil
	}
	return &user
}

func DBFindAllUserAttrs(tenant primitive.ObjectID) []UserAttr {
	var userAttrs []UserAttr

	cursor, err := userAttrCltn.Find(context.TODO(), bson.M{"tenant": tenant})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &userAttrs)
	if err != nil {
		return nil
	}

	return userAttrs
}

func DBDelUserAttr(tenant primitive.ObjectID, userid string) error {
	_, err := userAttrCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": userid, "tenant": tenant},
	)

	return err
}

type Bundle struct {
	Bid        string             `json:"bid" bson:"_id"`
	Tenant     primitive.ObjectID `json:"tenant" bson:"tenant"`
	Bundlename string             `json:"name" bson:"name"`
}

// This API will add/update a new bundle
func DBAddBundle(data *Bundle) error {

	if DBFindTenant(data.Tenant) == nil {
		return fmt.Errorf("Unknown tenant")
	}

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := appCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Bid, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"_id": data.Bid, "tenant": data.Tenant, "name": data.Bundlename}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindBundle(tenant primitive.ObjectID, bundleid string) *Bundle {
	var app Bundle
	err := appCltn.FindOne(
		context.TODO(),
		bson.M{"_id": bundleid, "tenant": tenant},
	).Decode(&app)
	if err != nil {
		return nil
	}
	return &app
}

func DBFindAllBundles(tenant primitive.ObjectID) []Bundle {
	var bundles []Bundle

	cursor, err := appCltn.Find(context.TODO(), bson.M{"tenant": tenant})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &bundles)
	if err != nil {
		return nil
	}

	return bundles
}

func DBDelBundle(tenant primitive.ObjectID, bundleid string) error {
	_, err := appCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": bundleid, "tenant": tenant},
	)
	return err
}

// This API will add/update a bundle Attribute Header
func DBAddBundleAttrHdr(data *DataHdr) error {

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := appAttrCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": "AppAttr", "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"_id": "AppAttr", "tenant": data.Tenant, "minver": data.Minver, "majver": data.Majver}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindBundleAttrHdr(tenant primitive.ObjectID) *DataHdr {
	var attr DataHdr
	err := appAttrCltn.FindOne(
		context.TODO(),
		bson.M{"_id": "AppAttr", "tenant": tenant},
	).Decode(&attr)
	if err != nil {
		return nil
	}
	return &attr
}

func DBDelBundleAttrHdr(tenant primitive.ObjectID) error {
	_, err := appAttrCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": "AppAttr", "tenant": tenant},
	)

	return err
}

type BundleAttr struct {
	Bid         string             `bson:"_id" json:"bid"`
	Tenant      primitive.ObjectID `bson:"tenant" json:"tenant"`
	Team        []string           `bson:"team" json:"team"`
	Dept        []string           `bson:"dept" json:"dept"`
	Contrib     string             `bson:"IC" json:"IC"`
	Manager     string             `bson:"manager" json:"manager"`
	Nonemployee string             `bson:"nonemployee" json:"nonemployee"`
}

// This API will add/update a bundle attribute
func DBAddBundleAttr(data *BundleAttr) error {

	if DBFindBundle(data.Tenant, data.Bid) == nil {
		return fmt.Errorf("Cannot find user")
	}

	// TODO: These versions have to be incremented
	hdr := DataHdr{Majver: "1", Minver: "0", Tenant: data.Tenant}
	DBAddBundleAttrHdr(&hdr)

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := appAttrCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Bid, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"_id": data.Bid, "tenant": data.Tenant, "team": data.Team, "dept": data.Dept,
				"IC": data.Contrib, "manager": data.Manager, "nonemployee": data.Nonemployee}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBFindBundleAttr(tenant primitive.ObjectID, bundleid string) *BundleAttr {
	var attr BundleAttr
	err := appAttrCltn.FindOne(
		context.TODO(),
		bson.M{"_id": bundleid, "tenant": tenant},
	).Decode(&attr)
	if err != nil {
		return nil
	}
	return &attr
}

func DBFindAllBundleAttrs(tenant primitive.ObjectID) []BundleAttr {
	var bundleAttrs []BundleAttr

	cursor, err := appAttrCltn.Find(context.TODO(), bson.M{"tenant": tenant})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &bundleAttrs)
	if err != nil {
		return nil
	}

	return bundleAttrs
}

func DBDelBundleAttr(tenant primitive.ObjectID, bundleid string) error {
	_, err := appAttrCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": bundleid, "tenant": tenant},
	)

	return err
}
