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

const HDRKEY = "Header"

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
		_ = DBDelTenantDocOnly(data.ID)
		return err
	}
	dbAddTenantDB(data.ID)
	// Add header docs for all attribute collections of tenant
	DBAddTenantCollectionHdrs(data.ID)

	return nil
}

func DBAddTenantCollectionHdrs(tenant primitive.ObjectID) {
	hdr := DataHdr{Majver: 1, Minver: 0, Tenant: tenant}

	_ = DBAddUserInfoHdr(&hdr)
	_ = DBAddUserAttrHdr(&hdr)
	_ = DBAddBundleInfoHdr(&hdr)
	_ = DBAddBundleAttrHdr(&hdr)
	_ = DBAddHostAttrHdr(&hdr)
}
	
func DBDelTenantCollectionHdrs(tenant primitive.ObjectID) {

	_ = DBDelUserInfoHdr(tenant)
	_ = DBDelUserAttrHdr(tenant)
	_ = DBDelBundleInfoHdr(tenant)
	_ = DBDelBundleAttrHdr(tenant)
	_ = DBDelHostAttrHdr(tenant)
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
	_ = DBDelNamespace(id)

	// Delete header docs of all attribute collections
	DBDelTenantCollectionHdrs(id)
	dbDelTenantDB(id)

	return nil
}

func DBDelTenantDocOnly(id primitive.ObjectID) error {
	_, err := tenantCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": id},
	)

	return err
}

//---------------------------Certificate functions---------------------------

// NOTE: The bson decoder will not work if the structure field names dont start with upper case
type Certificate struct {
	Certid string `json:"certid" bson:"_id"`
	Cert   []rune `json:"cert" bson:"cert"`
}

// This API will add a new certificate or update a certificate if it already exists
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

// This API will delete a certificate
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

//----------------------------Gateway functions--------------------------

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

//------------------------Collection header functions-------------------------

type DataHdr struct {
	ID     string             `bson:"_id" json:"ID"`
	Majver int                `bson:"majver" json:"majver"`
	Minver int                `bson:"minver" json:"minver"`
	Tenant primitive.ObjectID `bson:"tenant" json:"tenant"`
}

func DBGetHdrKey(val string) string {
	if nxtMongoVer >= 1 {
		return HDRKEY  // common name for all header docs
	}
	return val  // legacy name
}

func DBAddCollectionHdr(data *DataHdr, htype string, hkey string) error {
	// The upsert option asks the DB to add  if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	Cltn := dbGetCollection(data.Tenant, htype)
	if Cltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	hdockey := DBGetHdrKey(hkey)
	err := Cltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": hdockey, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"minver": data.Minver, "majver": data.Majver}},
		},
		&opt,
	)
	return err.Err()
}

func DBFindCollectionHdr(tenant primitive.ObjectID, htype string, hkey string) *DataHdr {
	var hdr DataHdr
	Cltn := dbGetCollection(tenant, htype)
	if Cltn == nil {
		return nil
	}
	hdockey := DBGetHdrKey(hkey)
	err := Cltn.FindOne(
		context.TODO(),
		bson.M{"_id": hdockey, "tenant": tenant},
	).Decode(&hdr)
	if err != nil {
		return nil
	}
	return &hdr
}

func DBDelCollectionHdr(tenant primitive.ObjectID, htype string, hkey string) error {

	Cltn := dbGetCollection(tenant, htype)
	if Cltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	hdockey := DBGetHdrKey(hkey)
	_, err := Cltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": hdockey, "tenant": tenant},
	)
	return err
}

//--------------------------User Info and Attributes---------=-------------------

// This API will add/update a user info Header
func DBAddUserInfoHdr(data *DataHdr) error {

	return DBAddCollectionHdr(data, "NxtUsers", "UserInfo")
}

func DBFindUserInfoHdr(tenant primitive.ObjectID) *DataHdr {
	
	return DBFindCollectionHdr(tenant, "NxtUsers", "UserInfo")
}

func DBDelUserInfoHdr(tenant primitive.ObjectID) error {

	return DBDelCollectionHdr(tenant, "NxtUsers", "UserInfo")
}

// This API will add/update a user Attribute Header
func DBAddUserAttrHdr(data *DataHdr) error {

	return DBAddCollectionHdr(data, "NxtUserAttr", "UserAttr")
}

func DBFindUserAttrHdr(tenant primitive.ObjectID) *DataHdr {
	
	return DBFindCollectionHdr(tenant, "NxtUserAttr", "UserAttr")
}

func DBDelUserAttrHdr(tenant primitive.ObjectID) error {
	_ = DBDelUserExtAttr(tenant)
	return DBDelCollectionHdr(tenant, "NxtUserAttr", "UserAttr")
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
	
	userCltn := dbGetCollection(data.Tenant, "NxtUsers")
	if userCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	result := userCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Uid, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"name": data.Username, "email": data.Email,
				"gateway": data.Gateway, "pod": data.Pod, "connectid": data.Connectid,
				"services": data.Services}},
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
	var user bson.M

	tenants := DBFindAllTenants()
	for i := 0; i < len(tenants); i++ {
		userCltn := dbGetCollection(tenants[i].ID, "NxtUsers")
		if userCltn != nil {
			err := userCltn.FindOne(
				context.TODO(),
				bson.M{"_id": userid, "tenant": tenants[i].ID},
			).Decode(&user)
			if err == nil {
				return &tenants[i].ID
			}
		}
	}
	return nil
}

func DBFindUser(tenant primitive.ObjectID, userid string) *User {
	var user User
	userCltn := dbGetCollection(tenant, "NxtUsers")
	if userCltn == nil {
		return nil
	}
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

	userCltn := dbGetCollection(tenant, "NxtUsers")
	if userCltn == nil {
		return nil
	}
	cursor, err := userCltn.Find(context.TODO(), bson.M{"tenant": tenant})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &users)
	if err != nil {
		return nil
	}

	if len(users) == 0 {
		return nil
	}
	hdockey := DBGetHdrKey("UserInfo")
	nusers := make([]bson.M, len(users))
	j := 0
	for i := 0; i < len(users); i++ {
		// Need to skip header doc
		uid := fmt.Sprintf("%s", users[i]["_id"])
		if uid != hdockey {
			nusers[j] = users[i]
			nusers[j]["uid"] = users[i]["_id"]
			delete(nusers[j], "_id")
			j++
		}
	}
	if len(nusers[:j]) == 0 {
		return nil
	}
	return nusers[:j]
}

func DBDelUser(tenant primitive.ObjectID, userid string) error {
	// TODO: Do not allow delete if user attribute doc exists
	
	userCltn := dbGetCollection(tenant, "NxtUsers")
	if userCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
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

// Sample user attributes schema. It is transparent to the controller.
//type UserAttr struct {
//	Uid      string             `bson:"_id" json:"uid"`
//	Tenant   primitive.ObjectID `bson:"tenant" json:"tenant"`
//	Category string             `bson:"category" json:"category"`
//	Type     string             `bson:"type" json:"type"`
//	Level    int                `bson:"level" json:"level"`
//	Dept     []string           `bson:"dept" json:"dept"`
//	Team     []string           `bson:"team" json:"team"`
//}

// This API will add a new user attributes doc or update existing one
func DBAddUserAttr(data []byte) error {
	var Uattr bson.M

	err := json.Unmarshal(data, &Uattr)
	if err != nil {
		return err
	}
	tenantstr := fmt.Sprintf("%s", Uattr["tenant"])
	tenant, _ := StrToObjectid(tenantstr)
	user := fmt.Sprintf("%s", Uattr["uid"])
	delete(Uattr, "uid")

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
	userAttrCltn := dbGetCollection(tenant, "NxtUserAttr")
	if userAttrCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	result := userAttrCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": user, "tenant": tenantstr},
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
	userAttrCltn := dbGetCollection(tenant, "NxtUserAttr")
	if userAttrCltn == nil {
		return nil
	}
	err := userAttrCltn.FindOne(
		context.TODO(),
		bson.M{"_id": userid, "tenant": tenant.Hex()},
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

	userAttrCltn := dbGetCollection(tenant, "NxtUserAttr")
	if userAttrCltn == nil {
		return nil
	}
	cursor, err := userAttrCltn.Find(context.TODO(), bson.M{"tenant": tenant.Hex()})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &userAttrs)
	if err != nil {
		return nil
	}

	if len(userAttrs) == 0 {
		return nil
	}
	hdockey := DBGetHdrKey("UserAttr")
	nuserAttrs := make([]bson.M, len(userAttrs))
	j := 0
	for i := 0; i < len(userAttrs); i++ {
		// Need to skip header doc
		uid := fmt.Sprintf("%s", userAttrs[i]["_id"])
		if (uid != hdockey) && (uid != "UserExtAttr") {
			nuserAttrs[j] = userAttrs[i]
			nuserAttrs[j]["uid"] = userAttrs[i]["_id"]
			delete(nuserAttrs[j], "_id")
			j++
		}
	}
	if len(nuserAttrs[:j]) == 0 {
		return nil
	}
	return nuserAttrs[:j]
}

func DBDelUserAttr(tenant primitive.ObjectID, userid string) error {
	userAttrCltn := dbGetCollection(tenant, "NxtUserAttr")
	if userAttrCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	_, err := userAttrCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": userid, "tenant": tenant.Hex()},
	)

	return err
}

//----------------------App bundle Info and Attributes-----------------------

// This API will add/update a bundle info Header
func DBAddBundleInfoHdr(data *DataHdr) error {

	return DBAddCollectionHdr(data, "NxtAppInfo", "AppInfo")
}

func DBFindBundleInfoHdr(tenant primitive.ObjectID) *DataHdr {

	return DBFindCollectionHdr(tenant, "NxtAppInfo", "AppInfo")
}

func DBDelBundleInfoHdr(tenant primitive.ObjectID) error {

	return DBDelCollectionHdr(tenant, "NxtAppInfo", "AppInfo")
}


// This API will add/update a bundle Attribute Header
func DBAddBundleAttrHdr(data *DataHdr) error {

	return DBAddCollectionHdr(data, "NxtAppAttr", "AppAttr")
}

func DBFindBundleAttrHdr(tenant primitive.ObjectID) *DataHdr {

	return DBFindCollectionHdr(tenant, "NxtAppAttr", "AppAttr")
}

func DBDelBundleAttrHdr(tenant primitive.ObjectID) error {

	return DBDelCollectionHdr(tenant, "NxtAppAttr", "AppAttr")
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
	appCltn := dbGetCollection(data.Tenant, "NxtApps")
	if appCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	result := appCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Bid, "tenant": data.Tenant},
		bson.D{
			{"$set", bson.M{"name": data.Bundlename,
				"gateway": data.Gateway, "pod": data.Pod, "connectid": data.Connectid,
				"services": data.Services}},
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

	tenants := DBFindAllTenants()
	for i := 0; i < len(tenants); i++ {
		appCltn := dbGetCollection(tenants[i].ID, "NxtApps")
		if appCltn != nil {
			err := appCltn.FindOne(
				context.TODO(),
				bson.M{"_id": bundleid, "tenant": tenants[i].ID},
			).Decode(&app)
			if err == nil {
				return &tenants[i].ID
			}
		}
	}
	return nil
}

func DBFindBundle(tenant primitive.ObjectID, bundleid string) *Bundle {
	var app Bundle
	appCltn := dbGetCollection(tenant, "NxtApps")
	if appCltn == nil {
		return nil
	}
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

	appCltn := dbGetCollection(tenant, "NxtApps")
	if appCltn == nil {
		return nil
	}
	cursor, err := appCltn.Find(context.TODO(), bson.M{"tenant": tenant})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &bundles)
	if err != nil {
		return nil
	}

	if len(bundles) == 0 {
		return nil
	}
	hdockey := DBGetHdrKey("AppInfo")
	nbundles := make([]bson.M, len(bundles))
	j := 0
	for i := 0; i < len(bundles); i++ {
		// Need to skip header doc
		bid := fmt.Sprintf("%s", bundles[i]["_id"])
		if bid != hdockey {
			nbundles[j] = bundles[i]
			nbundles[j]["bid"] = bundles[i]["_id"]
			delete(nbundles[j], "_id")
			j++
		}
	}
	if len(nbundles[:j]) == 0 {
		return nil
	}
	return nbundles[:j]
}

func DBDelBundle(tenant primitive.ObjectID, bundleid string) error {
	appCltn := dbGetCollection(tenant, "NxtApps")
	if appCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
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

// Sample app-bundle attributes schema. It is transparent to the controller.
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
	tenantstr := fmt.Sprintf("%s", Battr["tenant"])
	tenant, _ := StrToObjectid(tenantstr)
	bid := fmt.Sprintf("%s", Battr["bid"])
	delete(Battr, "bid")

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
	appAttrCltn := dbGetCollection(tenant, "NxtAppAttr")
	if appAttrCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	result := appAttrCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": bid, "tenant": tenantstr},
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
	appAttrCltn := dbGetCollection(tenant, "NxtAppAttr")
	if appAttrCltn == nil {
		return nil
	}
	err := appAttrCltn.FindOne(
		context.TODO(),
		bson.M{"_id": bundleid, "tenant": tenant.Hex()},
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

	appAttrCltn := dbGetCollection(tenant, "NxtAppAttr")
	if appAttrCltn == nil {
		return nil
	}
	cursor, err := appAttrCltn.Find(context.TODO(), bson.M{"tenant": tenant.Hex()})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &bundleAttrs)
	if err != nil {
		return nil
	}

	if len(bundleAttrs) == 0 {
		return nil
	}
	hdockey := DBGetHdrKey("AppAttr")
	nbundleAttrs := make([]bson.M, len(bundleAttrs))
	j := 0
	for i := 0; i < len(bundleAttrs); i++ {
		// Need to skip header doc
		bid := fmt.Sprintf("%s", bundleAttrs[i]["_id"])
		if bid != hdockey {
			nbundleAttrs[j] = bundleAttrs[i]
			nbundleAttrs[j]["bid"] = bundleAttrs[i]["_id"]
			delete(nbundleAttrs[j], "_id")
			j++
		}
	}
	if len(nbundleAttrs[:j]) == 0 {
		return nil
	}
	return nbundleAttrs[:j]
}

func DBDelBundleAttr(tenant primitive.ObjectID, bundleid string) error {
	appAttrCltn := dbGetCollection(tenant, "NxtAppAttr")
	if appAttrCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	_, err := appAttrCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": bundleid, "tenant": tenant.Hex()},
	)

	return err
}

//-------------------------------Host Attributes -------------------------

// This API will add/update a Host Attributes Header
func DBAddHostAttrHdr(data *DataHdr) error {

	return DBAddCollectionHdr(data, "NxtHostAttr", "HostAttr")

}

func DBFindHostAttrHdr(tenant primitive.ObjectID) *DataHdr {

	return DBFindCollectionHdr(tenant, "NxtHostAttr", "HostAttr")
}

func DBDelHostAttrHdr(tenant primitive.ObjectID) error {

	return DBDelCollectionHdr(tenant, "NxtHostAttr", "HostAttr")
}
	
func DBFindHostAttr(tenant primitive.ObjectID, host string) *bson.M {
	var Hattr bson.M
	hostAttrCltn := dbGetCollection(tenant, "NxtHostAttr")
	if hostAttrCltn == nil {
		return nil
	}
	err := hostAttrCltn.FindOne(
		context.TODO(),
		bson.M{"_id": host, "tenant": tenant.Hex()},
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

	hostAttrCltn := dbGetCollection(tenant, "NxtHostAttr")
	if hostAttrCltn == nil {
		return nil
	}
	cursor, err := hostAttrCltn.Find(context.TODO(), bson.M{"tenant": tenant.Hex()})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &hostAttrs)
	if err != nil {
		return nil
	}

	if len(hostAttrs) == 0 {
		return nil
	}
	hdockey := DBGetHdrKey("HostAttr")
	nhostAttrs := make([]bson.M, len(hostAttrs))
	j := 0
	for i := 0; i < len(hostAttrs); i++ {
		// Need to skip header doc
		host := fmt.Sprintf("%s", hostAttrs[i]["_id"])
		if host != hdockey {
			nhostAttrs[j] = hostAttrs[i]
			nhostAttrs[j]["host"] = hostAttrs[i]["_id"]
			delete(nhostAttrs[j], "_id")
			j++
		}
	}
	if len(nhostAttrs[:j]) == 0 {
		return nil
	}
	return nhostAttrs[:j]
}

// This API will add/update a host attributes doc
func DBAddHostAttr(data []byte) error {
	var Hattr bson.M

	err := json.Unmarshal(data, &Hattr)
	if err != nil {
		return err
	}
	tenantstr := fmt.Sprintf("%s", Hattr["tenant"])
	tenant, _ := StrToObjectid(tenantstr)
	host := fmt.Sprintf("%s", Hattr["host"])
	delete(Hattr, "host")

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
	hostAttrCltn := dbGetCollection(tenant, "NxtHostAttr")
	if hostAttrCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	result := hostAttrCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": host, "tenant": tenantstr},
		bson.D{{"$set", Hattr}},
		&opt,
	)
	if result.Err() != nil {
		return result.Err()

	}

	DBAddHostAttrHdr(hdr)

	return nil
}

func DBDelHostAttr(tenant primitive.ObjectID, hostid string) error {
	hostAttrCltn := dbGetCollection(tenant, "NxtHostAttr")
	if hostAttrCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
 	_, err := hostAttrCltn.DeleteOne(
 		context.TODO(),
		bson.M{"_id": hostid, "tenant": tenant.Hex()},
 	)
 
 	return err
 }

//----------------------------User extended attributes------------------------------

// User extended attributes are dynamic attributes, ie, atrributes that can
// change frequently, such as user location, user device o/s version, etc.
// These attributes are obtained from nextensio headers and combined with
// attributes read from mongoDB.
// The spec here gives a json string of key value pairs where the key is the
// attribute key as used in a OPA Rego query, and the value is the Nextensio
// header name. The Nextensio OPA library replaces the header
// name with the header value.
//type UserExtAttr struct {
//	ID       string             `bson:"_id" json:"ID"`
//	Tenant   primitive.ObjectID `bson:"tenant" json:"tenant"`
//	Attrlist string             `bson:"attrlist" json:"attrlist"`
//}

func DBFindUserExtAttr(tenant primitive.ObjectID) *bson.M {
	var attr bson.M
	userAttrCltn := dbGetCollection(tenant, "NxtUserAttr")
	if userAttrCltn == nil {
		return nil
	}
	err := userAttrCltn.FindOne(
		context.TODO(),
		bson.M{"_id": "UserExtAttr", "tenant": tenant.Hex()},
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
	tenantstr := fmt.Sprintf("%s", UEAttr["tenant"])
	tenant, _ := StrToObjectid(tenantstr)

	// The upsert option asks the DB to add  if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	userAttrCltn := dbGetCollection(tenant, "NxtUserAttr")
	if userAttrCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	rerr := userAttrCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": "UserExtAttr", "tenant": tenantstr},
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
	userAttrCltn := dbGetCollection(tenant, "NxtUserAttr")
	if userAttrCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	_, err := userAttrCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": "UserExtAttr", "tenant": tenant.Hex()},
	)

	return err
}
