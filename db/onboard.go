package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

//TODO: The usages of "FindAllXYZ" has to be audited and modified to a more appropriate form,
//it will be a killer as we scale to thousands of users / tenants etc.. And we will need the
//UI also to be modified to not use FindAllXYZ and instead find within a given range etc.

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
	Domains  []string           `json:"domains" bson:"domains"`
	Image    string             `json:"image" bson:"image"`
	Pods     int                `json:"pods" bson:"pods"`
	Curid    string             `json:"curid" bson:"curid"`
	NextPod  int                `json:"nextpod" bson:"nextpod"`
}

func tenantNextPod(tenant *Tenant) int {
	if tenant.Pods == 0 {
		return 0
	}
	nextpod := tenant.NextPod + 1 // Pods are created one-based
	tenant.NextPod = (tenant.NextPod + 1) % tenant.Pods
	tenant.Curid = tenant.ID.Hex()
	DBAddTenant(tenant)

	return nextpod
}

// This API will add a new tenant or update a tenant if it already exists
func DBAddTenant(data *Tenant) error {

	for i := 0; i < len(data.Gateways); i++ {
		if DBFindGateway(data.Gateways[i]) == nil {
			return fmt.Errorf("Gateway %s not configured", data.Gateways[i])
		}
	}

	change := bson.M{"name": data.Name, "gateways": data.Gateways, "domains": data.Domains,
		"image": data.Image, "pods": data.Pods, "nextpod": data.NextPod}
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

// NOTE: The bson decoder will not work if the structure field names dont start with upper case
type Certificate struct {
	Certid string `json:"certid" bson:"_id"`
	Cert   []rune `json:"cert" bson:"cert"`
}

// This API will add a new gateway or update a gateway if it already exists
func DBAddCert(data *Certificate) error {

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := certCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Certid},
		bson.D{
			{"$set", bson.M{"_id": data.Certid, "cert": data.Cert}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

// This API will delete a gateway if its not in use by any tenants
func DBDelCert(name string) error {

	_, err := certCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": name},
	)

	if err != nil {
		return err
	}
	return nil
}

func DBFindCert(name string) *Certificate {
	var cert Certificate
	err := certCltn.FindOne(
		context.TODO(),
		bson.M{"_id": name},
	).Decode(&cert)
	if err != nil {
		return nil
	}
	return &cert
}

func DBFindAllCerts() []Certificate {
	var certs []Certificate

	cursor, err := certCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &certs)
	if err != nil {
		return nil
	}

	return certs
}

type Gateway struct {
	Name string `json:"name" bson:"_id"`
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
			{"$set", bson.M{"_id": data.Name}},
		},
		&opt,
	)

	if err != nil {
		return err.Err()
	}
	return nil
}

func DBGatewayInUse(name string) bool {
	tenants := DBFindAllTenants()
	for _, t := range tenants {
		for _, n := range t.Gateways {
			if name == n {
				return true
			}
		}
	}
	return false
}

// This API will delete a gateway if its not in use by any tenants
func DBDelGateway(name string) error {

	_, err := gatewayCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": name},
	)

	if err != nil {
		return err
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
	Gateway   string             `json:"gateway" bson:"gateway"`
	Pod       int                `json:"pod" bson:"pod"`
	Connectid string             `json:"connectid" bson:"connectid"`
	Services  []string           `json:"services" bson:"services"`
}

// This API will add/update a new user
func DBAddUser(data *User) error {

	tenant := DBFindTenant(data.Tenant)
	if tenant == nil {
		return fmt.Errorf("Unknown tenant")
	}

	data.Gateway = strings.TrimSpace(data.Gateway)
	if data.Gateway != "" {
		if DBFindGateway(data.Gateway) == nil {
			return fmt.Errorf("Gateway %s not configured", data.Gateway)
		}
	}

	data.Services = delEmpty(data.Services)

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	// TODO:  need a a better algo for pod assignment
	if data.Pod == 0 {
		data.Pod = tenantNextPod(tenant)
	}
	// Replace @ and . (dot) in usernames/service-names with - (dash) - kuberenetes is
	// not happy with @, minion wants to replace dot with dash, keep everyone happy
	// TODO: Same user/uuid can login from multiple devices, in which case the connectid
	// has to be different, somehow figure out a scheme to make multiple connectids per user
	// Also the connectid eventually will be of a form where it is podNN-blah so that the
	// cluster yamls can just install one wildcard rule for podNN-* rather than a rule for
	// each user on that pod
	data.Connectid = strings.ReplaceAll(data.Uid, "@", "-")
	data.Connectid = strings.ReplaceAll(data.Connectid, ".", "-")
	result := userCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Uid, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"_id": data.Uid, "tenant": data.Tenant, "name": data.Username, "email": data.Email,
				"gateway": data.Gateway, "pod": data.Pod, "connectid": data.Connectid, "services": data.Services}},
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

func DBFindAllUsers(tenant primitive.ObjectID) []bson.M {
	var users []bson.M

	cursor, err := userCltn.Find(context.TODO(), bson.M{"tenant": tenant})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &users)
	if err != nil {
		return nil
	}

	for i := 0; i < len(users); i++ {
		users[i]["uid"] = users[i]["_id"]
		delete(users[i], "_id")
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
	_ = DBDelUserExtAttr(tenant)
	_, err := userAttrCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": "UserAttr", "tenant": tenant},
	)

	return err
}

//type UserAttr struct {
//	Uid      string             `bson:"_id" json:"uid"`
//	Tenant   primitive.ObjectID `bson:"tenant" json:"tenant"`
//	Category string             `bson:"category" json:"category"`
//	Type     string             `bson:"type" json:"type"`
//	Level    int                `bson:"level" json:"level"`
//	Dept     []string           `bson:"dept" json:"dept"`
//	Team     []string           `bson:"team" json:"team"`
//}

// This API will add a new/update user attributes
func DBAddUserAttr(data []byte) error {
	var Uattr bson.M

	err := json.Unmarshal(data, &Uattr)
	if err != nil {
		return err
	}
	tenant, _ := primitive.ObjectIDFromHex(fmt.Sprintf("%s", Uattr["tenant"]))
	user := fmt.Sprintf("%s", Uattr["uid"])
	delete(Uattr, "uid")
	delete(Uattr, "tenant")

	if DBFindUser(tenant, user) == nil {
		return fmt.Errorf("Cannot find user")
	}

	hdr := DBFindUserAttrHdr(tenant)
	if hdr == nil {
		dhdr := DataHdr{Majver: 1, Minver: 0, Tenant: tenant}
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
		bson.M{"_id": user, "tenant": tenant},
		bson.D{
			{"$set", Uattr},
		},
		&opt,
	)
	if result.Err() != nil {
		return result.Err()
	}

	DBAddUserAttrHdr(hdr)
	return nil
}

func DBFindUserAttr(tenant primitive.ObjectID, userid string) *bson.M {
	var user bson.M
	err := userAttrCltn.FindOne(
		context.TODO(),
		bson.M{"_id": userid, "tenant": tenant},
	).Decode(&user)
	if err != nil {
		return nil
	}
	user["uid"] = user["_id"]
	delete(user, "_id")
	return &user
}

func DBFindAllUserAttrs(tenant primitive.ObjectID) []bson.M {
	var userAttrs []bson.M

	cursor, err := userAttrCltn.Find(context.TODO(), bson.M{"tenant": tenant})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &userAttrs)
	if err != nil {
		return nil
	}

	for i := 0; i < len(userAttrs); i++ {
		userAttrs[i]["uid"] = userAttrs[i]["_id"]
		delete(userAttrs[i], "_id")
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
	Gateway    string             `json:"gateway" bson:"gateway"`
	Pod        int                `json:"pod" bson:"pod"`
	Connectid  string             `json:"connectid" bson:"connectid"`
	Services   []string           `json:"services" bson:"services"`
}

// This API will add/update a new bundle
func DBAddBundle(data *Bundle) error {

	tenant := DBFindTenant(data.Tenant)
	if tenant == nil {
		return fmt.Errorf("Unknown tenant")
	}

	data.Gateway = strings.TrimSpace(data.Gateway)
	if data.Gateway != "" {
		if DBFindGateway(data.Gateway) == nil {
			return fmt.Errorf("Gateway %s not configured", data.Gateway)
		}
	}

	data.Services = delEmpty(data.Services)

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	// TODO:  need a a better algo for pod assignment
	if data.Pod == 0 {
		data.Pod = tenantNextPod(tenant)
	}
	// Replace @ and . (dot) in usernames/service-names with - (dash) - kuberenetes is
	// not happy with @, minion wants to replace dot with dash, keep everyone happy
	// TODO: Same user/uuid can login from multiple devices, in which case the connectid
	// has to be different, somehow figure out a scheme to make multiple connectids per user
	// Also the connectid eventually will be of a form where it is podNN-blah so that the
	// cluster yamls can just install one wildcard rule for podNN-* rather than a rule for
	// each user on that pod
	data.Connectid = strings.ReplaceAll(data.Bid, "@", "-")
	data.Connectid = strings.ReplaceAll(data.Connectid, ".", "-")
	result := appCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Bid, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"_id": data.Bid, "tenant": data.Tenant, "name": data.Bundlename,
				"gateway": data.Gateway, "pod": data.Pod, "connectid": data.Connectid, "services": data.Services}},
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

// Purely used for the test environment where we dont want to do the full
// onboarding and return tenant id as part of onboarding etc.., instead
// just look for this user in any of the matching tenants - obviously
// assumption for test environment in that case is that username is unique
// across tenants
func DBFindBundleAnyTenant(bundleid string) *primitive.ObjectID {
	var app bson.M
	err := appCltn.FindOne(
		context.TODO(),
		bson.M{"_id": bundleid},
	).Decode(&app)
	if err != nil {
		return nil
	}
	t := app["tenant"].(primitive.ObjectID)
	return &t
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

func DBFindAllBundles(tenant primitive.ObjectID) []bson.M {
	var bundles []bson.M

	cursor, err := appCltn.Find(context.TODO(), bson.M{"tenant": tenant})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &bundles)
	if err != nil {
		return nil
	}

	for i := 0; i < len(bundles); i++ {
		bundles[i]["bid"] = bundles[i]["_id"]
		delete(bundles[i], "_id")
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

//type BundleAttr struct {
//	Bid         string             `bson:"_id" json:"bid"`
//	Tenant      primitive.ObjectID `bson:"tenant" json:"tenant"`
//	Team        []string           `bson:"team" json:"team"`
//	Dept        []string           `bson:"dept" json:"dept"`
//	Contrib     int                `bson:"IC" json:"IC"`
//	Manager     int                `bson:"manager" json:"manager"`
//	Nonemployee string             `bson:"nonemployee" json:"nonemployee"`
//}

// This API will add/update a bundle attribute
func DBAddBundleAttr(data []byte) error {
	var Battr bson.M

	err := json.Unmarshal(data, &Battr)
	if err != nil {
		return err
	}
	tenant, _ := primitive.ObjectIDFromHex(fmt.Sprintf("%s", Battr["tenant"]))
	bid := fmt.Sprintf("%s", Battr["bid"])
	delete(Battr, "bid")
	delete(Battr, "tenant")

	if DBFindBundle(tenant, bid) == nil {
		return fmt.Errorf("Cannot find bundle")
	}

	hdr := DBFindBundleAttrHdr(tenant)
	if hdr == nil {
		dhdr := DataHdr{Majver: 1, Minver: 0, Tenant: tenant}
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
		bson.M{"_id": bid, "tenant": tenant},
		bson.D{{"$set", Battr}},
		&opt,
	)
	if result.Err() != nil {
		return result.Err()
	}

	DBAddBundleAttrHdr(hdr)

	return nil
}

func DBFindBundleAttr(tenant primitive.ObjectID, bundleid string) *bson.M {
	var Battr bson.M
	err := appAttrCltn.FindOne(
		context.TODO(),
		bson.M{"_id": bundleid, "tenant": tenant},
	).Decode(&Battr)
	if err != nil {
		return nil
	}
	Battr["bid"] = Battr["_id"]
	delete(Battr, "_id")
	return &Battr
}

func DBFindAllBundleAttrs(tenant primitive.ObjectID) []bson.M {
	var bundleAttrs []bson.M

	cursor, err := appAttrCltn.Find(context.TODO(), bson.M{"tenant": tenant})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &bundleAttrs)
	if err != nil {
		return nil
	}

	for i := 0; i < len(bundleAttrs); i++ {
		bundleAttrs[i]["bid"] = bundleAttrs[i]["_id"]
		delete(bundleAttrs[i], "_id")
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

func DBFindHostAttrHdr(tenant primitive.ObjectID) *DataHdr {
	var attr DataHdr
	err := hostAttrCltn.FindOne(
		context.TODO(),
		bson.M{"_id": "HostAttr", "tenant": tenant},
	).Decode(&attr)
	if err != nil {
		return nil
	}
	return &attr
}

func DBFindHostAttr(tenant primitive.ObjectID, host string) *bson.M {
	var Hattr bson.M
	err := hostAttrCltn.FindOne(
		context.TODO(),
		bson.M{"_id": host, "tenant": tenant},
	).Decode(&Hattr)
	if err != nil {
		return nil
	}

	Hattr["host"] = Hattr["_id"]
	delete(Hattr, "_id")
	return &Hattr
}

func DBFindAllHostAttrs(tenant primitive.ObjectID) []bson.M {
	var hostAttrs []bson.M

	cursor, err := hostAttrCltn.Find(context.TODO(), bson.M{"tenant": tenant})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &hostAttrs)
	if err != nil {
		return nil
	}

	for i := 0; i < len(hostAttrs); i++ {
		hostAttrs[i]["host"] = hostAttrs[i]["_id"]
		delete(hostAttrs[i], "_id")
	}
	return hostAttrs
}

// This API will add/update a Host Attributes Header
func DBAddHostAttrHdr(data *DataHdr) error {

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := hostAttrCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": "HostAttr", "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"_id": "HostAttr", "tenant": data.Tenant,
				"minver": data.Minver, "majver": data.Majver}},
		},
		&opt,
	)
	if err != nil {
		return err.Err()
	}
	return nil
}

// This API will add/update a host attributes doc
func DBAddHostAttr(data []byte) error {
	var Hattr bson.M

	err := json.Unmarshal(data, &Hattr)
	if err != nil {
		return err
	}
	tenant, _ := primitive.ObjectIDFromHex(fmt.Sprintf("%s", Hattr["tenant"]))
	host := fmt.Sprintf("%s", Hattr["host"])
	delete(Hattr, "host")
	delete(Hattr, "tenant")

	hdr := DBFindHostAttrHdr(tenant)
	if hdr == nil {
		dhdr := DataHdr{Majver: 1, Minver: 0, Tenant: tenant}
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
	result := hostAttrCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": host, "tenant": tenant},
		bson.D{{"$set", Hattr}},
		&opt,
	)
	if result.Err() != nil {
		return result.Err()

	}

	DBAddHostAttrHdr(hdr)

	return nil
}

func DBDelHostAttrHdr(tenant primitive.ObjectID) error {
	_, err := hostAttrCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": "HostAttr", "tenant": tenant},
	)

	return err
}

func DBDelHostAttr(tenant primitive.ObjectID, hostid string) error {
	_, err := hostAttrCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": hostid, "tenant": tenant},
	)

	return err
}

// User attributes obtained from nextensio headers and combined with
// attributes read from mongoDB
//type UserExtAttr struct {
//	ID       string             `bson:"_id" json:"ID"`
//	Tenant   primitive.ObjectID `bson:"tenant" json:"tenant"`
//	Attrlist string             `bson:"attrlist" json:"attrlist"`
//}

func DBFindUserExtAttr(tenant primitive.ObjectID) *bson.M {
	var attr bson.M
	err := userAttrCltn.FindOne(
		context.TODO(),
		bson.M{"_id": "UserExtAttr", "tenant": tenant},
	).Decode(&attr)
	if err != nil {
		return nil
	}
	return &attr
}

// This API will add/update a user extended Attribute doc
func DBAddUserExtAttr(data []byte) error {
	var UEAttr bson.M

	err := json.Unmarshal(data, &UEAttr)
	if err != nil {
		return err
	}
	tenant, _ := primitive.ObjectIDFromHex(fmt.Sprintf("%s", UEAttr["tenant"]))
	delete(UEAttr, "tenant")

	// The upsert option asks the DB to add  if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	rerr := userAttrCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": "UserExtAttr", "tenant": tenant},
		bson.D{
			{"$set", UEAttr},
		},
		&opt,
	)

	if rerr.Err() != nil {
		return rerr.Err()

	}

	return nil
}

func DBDelUserExtAttr(tenant primitive.ObjectID) error {
	_, err := userAttrCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": "UserExtAttr", "tenant": tenant},
	)

	return err
}
