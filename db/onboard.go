package db

import (
	"context"
	"fmt"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func delEmpty(s []string) []string {
	var r []string
	for _, str := range s {
		if str != "" {
			r = append(r, str)
		}
	}
	return r
}

// NOTE: The bson decoder will not work if the structure field names dont start with upper case
type Tenant struct {
	ID       primitive.ObjectID `json:"_id" bson:"_id"`
	Name     string             `json:"name" bson:"name"`
	Gateways []string           `json:"gateways" bson:"gateways"`
	Image    string             `json:"image" bson:"image"`
	Pods     int                `json:"pods" bson:"pods"`
	Curid    string             `json:"curid" bson:"curid"`
}

// This API will add a new tenant or update a tenant if it already exists
func DBAddTenant(data *Tenant) error {

	for i := 0; i < len(data.Gateways); i++ {
		if DBFindGateway(data.Gateways[i]) == nil {
			return fmt.Errorf("Gateway %s not configured", data.Gateways[i])
		}
	}

	change := bson.M{"name": data.Name, "gateways": data.Gateways, "image": data.Image,
		"pods": data.Pods}
	ID, err := primitive.ObjectIDFromHex(data.Curid)
	if err == nil {
		filter := bson.D{{"_id", ID}}
		update := bson.D{{"$set", change}}
		_, err := tenantCltn.UpdateOne(
			context.TODO(),
			filter, update,
		)
		if err != nil {
			return err
		}
		data.ID = ID
	} else {
		result, err := tenantCltn.InsertOne(
			context.TODO(),
			change,
		)
		if err != nil {
			return err
		}
		data.ID, _ = result.InsertedID.(primitive.ObjectID)
	}

	err = DBAddNamespace(data)
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
	if err != nil {
		return err
	}
	err = DBDelNamespace(id)

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
	Uid       string             `json:"uid" bson:"_id"`
	Tenant    primitive.ObjectID `json:"tenant" bson:"tenant"`
	Username  string             `json:"name" bson:"name"`
	Email     string             `json:"email" bson:"email"`
	Pod       int                `json:"pod" bson:"pod"`
	Connectid string             `json:"connectid" bson:"connectid"`
	Services  []string           `json:"services" bson:"services"`
}

// This API will add/update a new user
func DBAddUser(data *User) error {

	if DBFindTenant(data.Tenant) == nil {
		return fmt.Errorf("Unknown tenant")
	}

	data.Services = delEmpty(data.Services)

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	// TODO: Pod assignment is set to 1 below, need an algo for pod assignment
	data.Pod = 1
	// Replace @ in email with -
	// TODO: Same user/uuid can login from multiple devices, in which case the connectid
	// has to be different, somehow figure out a scheme to make multiple connectids per user
	// Also the connectid eventually will be of a form where it is podNN-blah so that the
	// cluster yamls can just install one wildcard rule for podNN-* rather than a rule for
	// each user on that pod
	data.Connectid = strings.ReplaceAll(data.Uid, "@", "-")
	result := userCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Uid, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"_id": data.Uid, "tenant": data.Tenant, "name": data.Username, "email": data.Email,
				"pod": data.Pod, "services": data.Services}},
		},
		&opt,
	)

	if result.Err() != nil {
		return result.Err()
	}

	err := DBAddClusterUser(data)
	if err != nil {
		return err
	}

	return nil
}

// Purely used for the test environment where we dont want to do the full
// onboarding and return tenant id as part of onboarding etc.., instead
// just look for this user in any of the matching tenants - obviously
// assumption for test environment in that case is that username is unique
// across tenants
func DBFindUserAnyTenant(userid string) *primitive.ObjectID {
	var user User
	err := userCltn.FindOne(
		context.TODO(),
		bson.M{"_id": userid},
	).Decode(&user)
	if err != nil {
		return nil
	}
	return &user.Tenant
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
	if err != nil {
		return err
	}
	err = DBDelClusterUser(tenant, userid)
	if err != nil {
		return err
	}

	return nil
}

type DataHdr struct {
	ID     string             `bson:"_id" json:"ID"`
	Majver int                `bson:"majver" json:"majver"`
	Minver int                `bson:"minver" json:"minver"`
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
	Level    int                `bson:"level" json:"level"`
	Dept     []string           `bson:"dept" json:"dept"`
	Team     []string           `bson:"team" json:"team"`
}

// This API will add a new/update user attributes
func DBAddUserAttr(data *UserAttr) error {

	if DBFindUser(data.Tenant, data.Uid) == nil {
		return fmt.Errorf("Cannot find user")
	}

	hdr := DBFindUserAttrHdr(data.Tenant)
	if hdr == nil {
		dhdr := DataHdr{Majver: 1, Minver: 0, Tenant: data.Tenant}
		hdr = &dhdr
	} else {
		minver := hdr.Minver
		hdr.Minver = minver + 1
	}
	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	result := userAttrCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Uid, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"_id": data.Uid, "tenant": data.Tenant, "category": data.Category,
				"type": data.Type, "level": data.Level, "dept": data.Dept, "team": data.Team}},
		},
		&opt,
	)

	if result.Err() != nil {
		return result.Err()
	}

	DBAddUserAttrHdr(hdr)
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
	Pod        int                `json:"pod" bson:"pod"`
	Connectid  string             `json:"connectid" bson:"connectid"`
	Services   []string           `json:"services" bson:"services"`
}

// This API will add/update a new bundle
func DBAddBundle(data *Bundle) error {

	if DBFindTenant(data.Tenant) == nil {
		return fmt.Errorf("Unknown tenant")
	}

	data.Services = delEmpty(data.Services)

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	// TODO: Pod assignment is set to 1 below, need an algo for pod assignment
	data.Pod = 1
	// Replace @ in email with -
	// TODO: Same user/uuid can login from multiple devices, in which case the connectid
	// has to be different, somehow figure out a scheme to make multiple connectids per user
	// Also the connectid eventually will be of a form where it is podNN-blah so that the
	// cluster yamls can just install one wildcard rule for podNN-* rather than a rule for
	// each user on that pod
	data.Connectid = strings.ReplaceAll(data.Bid, "@", "-")
	result := appCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Bid, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"_id": data.Bid, "tenant": data.Tenant, "name": data.Bundlename,
				"pod": data.Pod, "services": data.Services}},
		},
		&opt,
	)
	if result.Err() != nil {
		return result.Err()
	}

	err := DBAddClusterBundle(data)
	if err != nil {
		return err
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
	if err != nil {
		return err
	}

	err = DBDelClusterUser(tenant, bundleid)
	if err != nil {
		return err
	}

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
	Contrib     int                `bson:"IC" json:"IC"`
	Manager     int                `bson:"manager" json:"manager"`
	Nonemployee string             `bson:"nonemployee" json:"nonemployee"`
}

// This API will add/update a bundle attribute
func DBAddBundleAttr(data *BundleAttr) error {

	if DBFindBundle(data.Tenant, data.Bid) == nil {
		return fmt.Errorf("Cannot find user")
	}

	hdr := DBFindBundleAttrHdr(data.Tenant)
	if hdr == nil {
		dhdr := DataHdr{Majver: 1, Minver: 0, Tenant: data.Tenant}
		hdr = &dhdr
	} else {
		minver := hdr.Minver
		hdr.Minver = minver + 1
	}

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	result := appAttrCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Bid, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"_id": data.Bid, "tenant": data.Tenant, "team": data.Team, "dept": data.Dept,
				"IC": data.Contrib, "manager": data.Manager, "nonemployee": data.Nonemployee}},
		},
		&opt,
	)

	if result.Err() != nil {
		return result.Err()
	}

	DBAddBundleAttrHdr(hdr)

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
