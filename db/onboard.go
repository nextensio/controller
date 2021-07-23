package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/golang/glog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const HDRKEY = "Header"

type Signup struct {
	Tenant string `json:"tenant" bson:"tenant"`
	Email  string `json:"email" bson:"email"`
}

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
	ID      string   `json:"_id" bson:"_id"`
	Name    string   `json:"name" bson:"name"`
	Domains []string `json:"domains" bson:"domains"`
}

func dbUpdateTenantDomains(uuid string) error {
	tenant := DBFindTenant(uuid)
	if tenant == nil {
		return errors.New("Cant find tenant")
	}
	hosts := DBFindAllHosts(uuid)

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}

	change := bson.M{"domains": hosts}
	err := tenantCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": tenant.ID},
		bson.D{
			{"$set", change},
		},
		&opt,
	)
	if err.Err() != nil {
		return err.Err()
	}
	return nil
}

func validateTenant(tenant string) bool {
	reg, _ := regexp.Compile("([a-z0-9]+)")
	match := reg.FindStringSubmatch(tenant)
	return len(match) == 2
}

// This API will add a new tenant or update a tenant if it already exists.
// Tenant additions are now not dependent on gateways/clusters. After adding
// the tenant, we link the tenant to one or more gateways/clusters via the
// TenantCluster configuration. This can be done incrementally. Tenants can be
// in different clusters using different number of minion allocations in each
// cluster.
func DBAddTenant(data *Tenant) error {

	if !validateTenant(data.ID) {
		return errors.New("invalid tenant id")
	}
	// See if tenant doc exists.
	tdoc := DBFindTenant(data.ID)

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}

	change := bson.M{"name": data.Name}
	err := tenantCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.ID},
		bson.D{
			{"$set", change},
		},
		&opt,
	)
	if err.Err() != nil {
		return err.Err()
	}

	e := DBAddNamespace(data)
	if e != nil {
		_ = DBDelTenantDocOnly(data.ID)
		return e
	}

	if tdoc == nil {
		// New tenant being added, so create logical DB for tenant
		// and add header docs for all attribute collections of tenant
		dbAddTenantDB(data.ID)
		DBAddTenantCollectionHdrs(data.ID)
	}

	return nil
}

func DBAddTenantCollectionHdrs(tenant string) {
	hdr := DataHdr{Majver: 1, Minver: 0}

	_ = DBAddUserInfoHdr(tenant, &hdr)
	_ = DBAddUserAttrHdr(tenant, &hdr)
	_ = DBAddBundleInfoHdr(tenant, &hdr)
	_ = DBAddBundleAttrHdr(tenant, &hdr)
	_ = DBAddHostAttrHdr(tenant, &hdr)
	// TenantCluster collection does not have a header doc for now
}

func DBDelTenantCollectionHdrs(tenant string) {

	_ = DBDelUserInfoHdr(tenant)
	_ = DBDelUserAttrHdr(tenant)
	_ = DBDelBundleInfoHdr(tenant)
	_ = DBDelBundleAttrHdr(tenant)
	_ = DBDelHostAttrHdr(tenant)
	// TenantCluster collection does not have a header doc for now
}

func DBFindTenant(id string) *Tenant {
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

// TODO: This API returns ALL gateways as of now, but a tenant
// might not have all gateways given to it, it might have a subset of all
// gateways. When that support comes in later, modify this to ensure it returns
// on the gateways assigned to this tenant
func DBFindAllGatewaysForTenant(tenant string) (error, []Gateway) {
	err, gws := DBFindAllGateways()
	if err != nil {
		return err, nil
	}
	return nil, gws
}

func DBDelTenant(id string) error {
	err, gws := DBFindAllGatewaysForTenant(id)
	if err != nil {
		return err
	}
	if gws != nil {
		return errors.New("Tenant assigned to clusters - cannot delete")
	}
	err = DBDelTenantDocOnly(id)
	if err != nil {
		return err
	}
	_ = DBDelNamespace(id)

	// Delete header docs of all attribute collections
	DBDelTenantCollectionHdrs(id)
	dbDelTenantDB(id)

	return nil
}

func DBDelTenantDocOnly(id string) error {
	_, err := tenantCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": id},
	)

	return err
}

//------------------------Tenant cluster functions-------------------------

// Per-tenant config to specify which clusters should have how many pods
// allocated for the tenant and which image to use for the pods. By default,
// the image is pulled from the tenant config but can be overridden per
// cluster. These docs are used to generate the global ClusterConfig collection
// which gives the per-cluster allocation of tenants and used as operational
// data by the clustermgr.
type TenantCluster struct {
	Id       string `json:"id" bson: "_id"` // TenantID:ClusterId
	Gateway  string `json:"gateway" bson:"gateway"`
	Image    string `json:"image" bson:"image"`
	ApodRepl int    `json:"apodrepl" bson:"apodrepl"`
	ApodSets int    `json:"apodsets" bson:"apodsets"`
}

// This API will add a tenant to a cluster or update one if it already exists
func DBAddTenantCluster(tenant string, data *TenantCluster) error {

	Cluster := DBGetClusterName(data.Gateway)

	err, gw := DBFindGateway(data.Gateway)
	if err != nil {
		return err
	}
	if gw == nil {
		return fmt.Errorf("Cannot find Gateway config for gateway %s", data.Gateway)
	}
	tdoc := DBFindTenant(tenant)
	if tdoc == nil {
		return fmt.Errorf("Unknown tenant %s", tenant)
	}
	tcl := DBFindTenantCluster(tenant, Cluster)
	if data.Image == "" {
		if tcl != nil {
			// just use the existing image
			data.Image = tcl.Image
		} else {
			// Default to image specified at tenant level
			data.Image = "registry.gitlab.com/nextensio/cluster/minion:latest"
		}
	}
	if data.ApodSets == 0 {
		if tcl != nil {
			data.ApodSets = tcl.ApodSets
		} else {
			data.ApodSets = 1
		}
	}
	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	tenantClusCltn := dbGetCollection(tenant, "NxtTenantClusters")
	if tenantClusCltn == nil {
		return fmt.Errorf("Unknown TenantClusters Collection")
	}
	id := tenant + ":" + Cluster
	result := tenantClusCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": id},
		bson.D{
			{"$set", bson.M{"tenant": tenant, "gateway": data.Gateway, "cluster": Cluster,
				"apodrepl": data.ApodRepl, "apodsets": data.ApodSets, "image": data.Image}},
		},
		&opt,
	)
	if result.Err() != nil {
		return result.Err()
	}
	// Add the cluster assignment config into the ClusterConfig collection that
	// maintains the configuration of each cluster for the cluster manager.
	_ = DBAddClusterConfig(tenant, data)
	return nil
}

// Find the doc for a specific cluster allocation of a given tenant
func DBFindTenantCluster(tid string, clid string) *TenantCluster {
	var tenantclus TenantCluster

	tenantClusCltn := dbGetCollection(tid, "NxtTenantClusters")
	if tenantClusCltn == nil {
		return nil
	}
	err := tenantClusCltn.FindOne(
		context.TODO(),
		bson.M{"_id": tid + ":" + clid},
	).Decode(&tenantclus)
	if err != nil {
		return nil
	}
	return &tenantclus
}

// Find all clusters configured/assigned to a tenant
func DBFindAllClusterConfigsForTenant(tid string) []TenantCluster {
	var tenantcls []TenantCluster

	tenantClusCltn := dbGetCollection(tid, "NxtTenantClusters")
	if tenantClusCltn == nil {
		return nil
	}
	cursor, err := tenantClusCltn.Find(context.TODO(), bson.M{"tenant": tid})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &tenantcls)
	if err != nil {
		return nil
	}

	return tenantcls
}

func DBDelTenantCluster(tid string, clid string) error {

	// Before removing the allocation of a tenant in a cluster, since we
	// have already created a ClusterConfig doc, we need to ensure first
	// that all pods of the tenant in the cluster are not in use.
	// TODO: figure out how to take pods out of service and then improve
	// the deletion of a tenant's cluster assignment.
	err := DBDelClusterConfig(clid, tid)
	if err != nil {
		return err
	}

	tenantClusCltn := dbGetCollection(tid, "NxtTenantClusters")
	if tenantClusCltn == nil {
		return fmt.Errorf("Unknown TenantClusters Collection")
	}
	_, err = tenantClusCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": tid + ":" + clid},
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

	if err.Err() != nil {
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
	Name     string `json:"name" bson:"_id"`
	Location string `json:"location" bson:"location"`
	Zone     string `json:"zone" bson:"zone"`
	Region   string `json:"region" bson:"region"`
	Provider string `json:"provider" bson:"provider"`
}

func DBGetClusterName(gateway string) string {
	if len(gateway) <= len(".nextensio.net") {
		return "unknown"
	}
	end := len(gateway) - len(".nextensio.net")
	return gateway[0:end]
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
			{"$set", bson.M{"location": data.Location,
				"zone": data.Zone, "region": data.Region,
				"provider": data.Provider}},
		},
		&opt,
	)

	if err.Err() != nil {
		return err.Err()
	}

	e := DBAddClusterGateway(data)
	if e != nil {
		_ = DBDelGateway(data.Name)
		return e
	}

	return nil
}

func DBGatewayInUse(gwname string) (error, bool) {
	err, gw := DBFindGateway(gwname)
	if err != nil {
		return err, false
	}
	if gw == nil {
		return nil, false
	}
	Cluster := DBGetClusterName(gw.Name)
	return DBAnyTenantsInCluster(Cluster)
}

// This API will delete a gateway if its not in use by any tenants
func DBDelGateway(name string) error {

	err, gw := DBFindGateway(name)
	if err != nil {
		return err
	}
	if gw == nil {
		// Gateway doesn't exist. Return silently
		return nil
	}
	Cluster := DBGetClusterName(gw.Name)
	err, inuse := DBAnyTenantsInCluster(Cluster)
	if err != nil {
		return err
	}
	if inuse {
		// Gateway has tenants allocated.
		return errors.New("Gateway in use - cannot delete")
	}
	_, err = gatewayCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": name},
	)

	if err != nil {
		return err
	}

	e := DBDelClusterGateway(name)
	if e != nil {
		return e
	}

	return nil
}

func DBFindGateway(name string) (error, *Gateway) {
	var gateway Gateway
	err := gatewayCltn.FindOne(
		context.TODO(),
		bson.M{"_id": name},
	).Decode(&gateway)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return err, nil
	}
	return nil, &gateway
}

func DBFindAllGateways() (error, []Gateway) {
	var gateways []Gateway

	cursor, err := gatewayCltn.Find(context.TODO(), bson.M{})
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return err, nil
	}
	err = cursor.All(context.TODO(), &gateways)
	if err != nil {
		return err, nil
	}

	return nil, gateways
}

//------------------------Attribute set functions-----------------------------
type AttrSet struct {
	Name      string `bson:"name" json:"name"`
	AppliesTo string `bson:"appliesTo" json:"appliesTo"`
	Type      string `bson:"type" json:"type"`
	IsArray   string `bson:"isArray" json:"isArray"`
}

func DBAddAttrSet(tenant string, s AttrSet) error {
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	Cltn := dbGetCollection(tenant, "NxtAttrSet")
	if Cltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	err := Cltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": s.Name + ":" + s.AppliesTo},
		bson.D{
			{"$set", bson.M{"name": s.Name, "appliesTo": s.AppliesTo,
				"type": s.Type, "isArray": s.IsArray}},
		},
		&opt,
	)
	if err.Err() != nil {
		glog.Errorf("AttrSet: Add error - %v", err)
		return err.Err()
	}
	if s.AppliesTo == "Hosts" {
		if err := DBAddAllHostsOneAttr(tenant, s); err != nil {
			return err
		}
	}
	if s.AppliesTo == "Users" {
		if err := DBAddAllUsersOneAttr(tenant, s); err != nil {
			return err
		}
	}
	if s.AppliesTo == "Bundles" {
		if err := DBAddAllBundlesOneAttr(tenant, s); err != nil {
			return err
		}
	}
	return nil
}

func DBDelAttrSet(tenant string, set AttrSet) error {
	Cltn := dbGetCollection(tenant, "NxtAttrSet")
	if Cltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	if set.AppliesTo == "Hosts" {
		if err := DBDelAllHostsOneAttr(tenant, set.Name); err != nil {
			return err
		}
	}
	if set.AppliesTo == "Users" {
		if err := DBDelAllUsersOneAttr(tenant, set.Name); err != nil {
			return err
		}
	}
	if set.AppliesTo == "Bundles" {
		if err := DBDelAllBundlesOneAttr(tenant, set.Name); err != nil {
			return err
		}
	}
	_, err := Cltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": set.Name + ":" + set.AppliesTo},
	)
	if err != nil {
		return err
	}

	return nil
}

func DBFindAllAttrSet(tenant string) []AttrSet {
	var set []AttrSet

	attrSetCltn := dbGetCollection(tenant, "NxtAttrSet")
	cursor, err := attrSetCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &set)
	if err != nil {
		glog.Errorf("AttrSet: Find all attr sets failed - %v", err)
		return nil
	}

	return set
}

//------------------------Collection header functions-------------------------

type DataHdr struct {
	ID     string `bson:"_id" json:"ID"`
	Majver int    `bson:"majver" json:"majver"`
	Minver int    `bson:"minver" json:"minver"`
}

func DBGetHdrKey(val string) string {
	return HDRKEY // common name for all header docs
}

func DBAddCollectionHdr(uuid string, data *DataHdr, htype string, hkey string) error {
	// The upsert option asks the DB to add  if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	Cltn := dbGetCollection(uuid, htype)
	if Cltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	hdockey := DBGetHdrKey(hkey)
	err := Cltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": hdockey},
		bson.D{
			{"$set", bson.M{"minver": data.Minver, "majver": data.Majver}},
		},
		&opt,
	)
	return err.Err()
}

func DBFindCollectionHdr(tenant string, htype string, hkey string) *DataHdr {
	var hdr DataHdr
	Cltn := dbGetCollection(tenant, htype)
	if Cltn == nil {
		return nil
	}
	hdockey := DBGetHdrKey(hkey)
	err := Cltn.FindOne(
		context.TODO(),
		bson.M{"_id": hdockey},
	).Decode(&hdr)
	if err != nil {
		return nil
	}
	return &hdr
}

func DBDelCollectionHdr(tenant string, htype string, hkey string) error {

	Cltn := dbGetCollection(tenant, htype)
	if Cltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	hdockey := DBGetHdrKey(hkey)
	_, err := Cltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": hdockey},
	)
	return err
}

//--------------------------User Info and Attributes---------=-------------------

// This API will add/update a user info Header
func DBAddUserInfoHdr(uuid string, data *DataHdr) error {

	return DBAddCollectionHdr(uuid, data, "NxtUsers", "UserInfo")
}

func DBFindUserInfoHdr(tenant string) *DataHdr {

	return DBFindCollectionHdr(tenant, "NxtUsers", "UserInfo")
}

func DBDelUserInfoHdr(tenant string) error {

	return DBDelCollectionHdr(tenant, "NxtUsers", "UserInfo")
}

// This API will add/update a user Attribute Header
func DBAddUserAttrHdr(uuid string, data *DataHdr) error {

	return DBAddCollectionHdr(uuid, data, "NxtUserAttr", "UserAttr")
}

func DBFindUserAttrHdr(tenant string) *DataHdr {

	return DBFindCollectionHdr(tenant, "NxtUserAttr", "UserAttr")
}

func DBDelUserAttrHdr(tenant string) error {
	_ = DBDelUserExtAttr(tenant)
	return DBDelCollectionHdr(tenant, "NxtUserAttr", "UserAttr")
}

// The Pod here indicates the "pod set" that this user should
// connect to, each pod set has its own number of replicas etc..
type User struct {
	Uid       string   `json:"uid" bson:"_id"`
	Username  string   `json:"name" bson:"name"`
	Email     string   `json:"email" bson:"email"`
	Gateway   string   `json:"gateway" bson:"gateway"`
	Pod       int      `json:"pod" bson:"pod"`
	Connectid string   `json:"connectid" bson:"connectid"`
	Services  []string `json:"services" bson:"services"`
}

// This API will add/update a new user
func DBAddUser(uuid string, data *User) error {

	tenant := DBFindTenant(uuid)
	if tenant == nil {
		return fmt.Errorf("Unknown tenant")
	}
	user := DBFindUser(uuid, data.Uid)

	// In our test setup, we preassign the gateway/cluster and pod.
	// In a real deployment, the gateway/cluster and pod have to be dynamically
	// assigned when a user agent is on-boarded.
	// If gateway/cluster is assigned, ensure it is valid, ie., in our configuration.
	// TODO: handle cluster/pod assignment when user connects via multiple devices.
	data.Gateway = strings.TrimSpace(data.Gateway)
	if data.Gateway != "" {
		// Ensure any gateway specified is valid
		err, gw := DBFindGateway(data.Gateway)
		if err != nil {
			return err
		}
		if gw == nil {
			return fmt.Errorf("Gateway %s not configured", data.Gateway)
		}
	} else {
		gw := "gateway.nextensio.net"
		// If user already has a gateway set then just use that
		if user != nil {
			if user.Gateway != "" {
				gw = user.Gateway
			}
		}
		// Neither cluster nor gw configured. Let user agent select the exact gw
		// by dns resolving gateway.nextensio.net to gatewayXYZ.nextensio.net
		data.Gateway = gw
	}

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	// By pod what we mean here is actually the "pod set" - ie of a set of
	// pods available (each with their own replicas). By default, users/agents
	// will have just one set with ApodRepl number of replicas
	if data.Pod == 0 {
		if user != nil {
			if user.Pod != 0 {
				data.Pod = user.Pod
			}
		}
	}
	if data.Pod == 0 {
		data.Pod = 1
	}

	// Replace @ and . (dot) in usernames/service-names with - (dash) - kuberenetes is
	// not happy with @, minion wants to replace dot with dash, keep everyone happy.
	// A user will have just one service, based on "tenant-userid"
	service := strings.ReplaceAll(uuid+"-"+data.Uid, "@", "-")
	service = strings.ReplaceAll(service, ".", "-")
	data.Services = []string{service}

	// Same user/uuid can login from multiple devices. The connectid will be based on the
	// pod assigned to each user device when on-boarding. Here we just initialize it to
	// any pre-configured pod. It may change during on-boarding.
	data.Connectid = ClusterGetApodSetName(uuid, data.Pod)

	userCltn := dbGetCollection(uuid, "NxtUsers")
	if userCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	result := userCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Uid},
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

	return nil
}

func DBFindUser(tenant string, userid string) *User {
	var user User
	userCltn := dbGetCollection(tenant, "NxtUsers")
	if userCltn == nil {
		return nil
	}
	err := userCltn.FindOne(
		context.TODO(),
		bson.M{"_id": userid},
	).Decode(&user)
	if err != nil {
		return nil
	}
	return &user
}

func DBFindAllUsers(tenant string) []bson.M {
	var users []bson.M

	userCltn := dbGetCollection(tenant, "NxtUsers")
	if userCltn == nil {
		return nil
	}
	cursor, err := userCltn.Find(context.TODO(), bson.M{})
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

func DBDelUser(tenant string, userid string) error {
	// TODO: Do not allow delete if user attribute doc exists
	var user User

	userCltn := dbGetCollection(tenant, "NxtUsers")
	if userCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	err := userCltn.FindOne(context.TODO(), bson.M{"_id": userid}).Decode(&user)
	if err != nil {
		return fmt.Errorf("Request to delete unknown user %s", userid)
	}
	_, err = userCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": userid},
	)
	if err != nil {
		return err
	}

	return nil
}

func dbAddUserAttr(uuid string, user string, Uattr bson.M, replace bool) error {
	hdr := DBFindUserAttrHdr(uuid)
	if hdr == nil {
		dhdr := DataHdr{Majver: 1, Minver: 0}
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
	userAttrCltn := dbGetCollection(uuid, "NxtUserAttr")
	if userAttrCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	if !replace {
		result := userAttrCltn.FindOneAndUpdate(
			context.TODO(),
			bson.M{"_id": user},
			bson.D{
				{"$set", Uattr},
			},
			&opt,
		)
		if result.Err() != nil {
			return result.Err()
		}
	} else {
		result, err := userAttrCltn.ReplaceOne(
			context.TODO(),
			bson.M{"_id": user},
			Uattr,
		)
		if err != nil {
			return err
		}
		if result.MatchedCount == 0 {
			return fmt.Errorf("Did not update any user")
		}
	}

	return DBAddUserAttrHdr(uuid, hdr)
}

// Sample user attributes schema. It is transparent to the controller.
//type UserAttr struct {
//	Uid      string             `bson:"_id" json:"uid"`
//	Tenant   string             `bson:"tenant" json:"tenant"`
//	Category string             `bson:"category" json:"category"`
//	Type     string             `bson:"type" json:"type"`
//	Level    int                `bson:"level" json:"level"`
//	Dept     []string           `bson:"dept" json:"dept"`
//	Team     []string           `bson:"team" json:"team"`
//}

// This API will add a new user attributes doc or update existing one
func DBAddUserAttr(uuid string, user string, Uattr bson.M) error {
	if Uattr != nil {
		attrset := DBFindAllAttrSet(uuid)
		nattrs := 0
		for _, a := range attrset {
			if a.AppliesTo == "Users" {
				nattrs += 1
				found := false
				for k := range Uattr {
					if k == a.Name {
						found = true
					}
				}
				if !found {
					return fmt.Errorf("All attributes defined in AttributeEditor needs to have some valid value provided", a.Name)
				}
			}
		}
	}
	if Uattr == nil {
		attr := DBFindUserAttr(uuid, user)
		if attr != nil {
			Uattr = *attr
			delete(Uattr, "uid")
		} else {
			Uattr = make(bson.M)
		}
	}
	dbUser := DBFindUser(uuid, user)
	if dbUser == nil {
		return fmt.Errorf("Cannot find user")
	}

	// Add the "base" attributes here which are like user email, pod etc..
	// These attributes will start with an underscore just to indicate that
	// these are not customer defined attributes. We will let customer know
	// about some attributes like _email which they can use in their policies
	Uattr["_email"] = dbUser.Email
	Uattr["_pod"] = fmt.Sprintf("apod%d", dbUser.Pod)
	Uattr["_gateway"] = dbUser.Gateway

	return dbAddUserAttr(uuid, user, Uattr, false)
}

func DBFindUserAttr(tenant string, userid string) *bson.M {
	var user bson.M
	userAttrCltn := dbGetCollection(tenant, "NxtUserAttr")
	if userAttrCltn == nil {
		return nil
	}
	err := userAttrCltn.FindOne(
		context.TODO(),
		bson.M{"_id": userid},
	).Decode(&user)
	if err != nil {
		return nil
	}
	user["uid"] = user["_id"]
	delete(user, "_id")
	return &user
}

func DBFindAllUserAttrs(tenant string) []bson.M {
	var userAttrs []bson.M

	userAttrCltn := dbGetCollection(tenant, "NxtUserAttr")
	if userAttrCltn == nil {
		return nil
	}
	cursor, err := userAttrCltn.Find(context.TODO(), bson.M{})
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

func DBDelUserAttr(tenant string, userid string) error {
	userAttrCltn := dbGetCollection(tenant, "NxtUserAttr")
	if userAttrCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	_, err := userAttrCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": userid},
	)

	return err
}

func DBDelAllUsersOneAttr(tenant string, todel string) error {
	var attr bson.M

	userAttrCltn := dbGetCollection(tenant, "NxtUserAttr")
	if userAttrCltn == nil {
		return fmt.Errorf("Cant find user collection")
	}
	cursor, err := userAttrCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return err
	}
	defer cursor.Close(context.TODO())
	for cursor.Next(context.TODO()) {
		if err = cursor.Decode(&attr); err != nil {
			return err
		}
		delete(attr, todel)
		if err := dbAddUserAttr(tenant, attr["_id"].(string), attr, true); err != nil {
			return err
		}
	}
	return nil
}

func DBAddAllUsersOneAttr(tenant string, set AttrSet) error {
	var attr bson.M

	userAttrCltn := dbGetCollection(tenant, "NxtUserAttr")
	if userAttrCltn == nil {
		return fmt.Errorf("Cant find user collection")
	}
	cursor, err := userAttrCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return err
	}

	value := defaultType(set)

	defer cursor.Close(context.TODO())
	for cursor.Next(context.TODO()) {
		if err = cursor.Decode(&attr); err != nil {
			return err
		}
		attr[set.Name] = value
		if err := dbAddUserAttr(tenant, attr["_id"].(string), attr, true); err != nil {
			return err
		}
	}
	return nil
}

//----------------------App bundle Info and Attributes-----------------------

// This API will add/update a bundle info Header
func DBAddBundleInfoHdr(uuid string, data *DataHdr) error {

	return DBAddCollectionHdr(uuid, data, "NxtAppInfo", "AppInfo")
}

func DBFindBundleInfoHdr(tenant string) *DataHdr {

	return DBFindCollectionHdr(tenant, "NxtAppInfo", "AppInfo")
}

func DBDelBundleInfoHdr(tenant string) error {

	return DBDelCollectionHdr(tenant, "NxtAppInfo", "AppInfo")
}

// This API will add/update a bundle Attribute Header
func DBAddBundleAttrHdr(uuid string, data *DataHdr) error {

	return DBAddCollectionHdr(uuid, data, "NxtAppAttr", "AppAttr")
}

func DBFindBundleAttrHdr(tenant string) *DataHdr {

	return DBFindCollectionHdr(tenant, "NxtAppAttr", "AppAttr")
}

func DBDelBundleAttrHdr(tenant string) error {

	return DBDelCollectionHdr(tenant, "NxtAppAttr", "AppAttr")
}

// The Pod here indicates the "pod set" that this user should
// connect to, each pod set has its own number of replicas etc..
type Bundle struct {
	Bid        string   `json:"bid" bson:"_id"`
	Bundlename string   `json:"name" bson:"name"`
	Gateway    string   `json:"gateway" bson:"gateway"`
	Pod        string   `json:"pod" bson:"pod"`
	Connectid  string   `json:"connectid" bson:"connectid"`
	Services   []string `json:"services" bson:"services"`
	CpodRepl   int      `json:"cpodrepl" bson:"cpodrepl"`
}

// This API will add/update a new bundle
func DBAddBundle(uuid string, data *Bundle) error {

	tenant := DBFindTenant(uuid)
	if tenant == nil {
		return fmt.Errorf("Unknown tenant")
	}
	bundle := DBFindBundle(uuid, data.Bid)

	// We currently preassign the gateway/cluster and pod. This may change to
	// just the cluster assignment if k8s does the pod assignment from amongst
	// a replicaset. TBD whether the cluster assignment should be dynamic when
	// connector signs-in.
	// If gateway/cluster is preassigned, ensure it is valid (in our config).
	data.Gateway = strings.TrimSpace(data.Gateway)
	if data.Gateway == "" {
		if bundle != nil {
			if bundle.Gateway != "" {
				data.Gateway = bundle.Gateway
			}
		}
	}
	if data.Gateway != "" {
		err, gw := DBFindGateway(data.Gateway)
		if err != nil {
			return err
		}
		if gw == nil {
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
	// By pod what we mean here is actually the "pod set" - ie of a set of
	// pods available (each with their own replicas), which set do we want to
	// connect to. This is an option for the admin to override the default that
	// clustermgr decides (the pod set with the name of the bundle)
	if data.Pod == "" {
		if bundle != nil {
			if bundle.Pod != "" {
				data.Pod = bundle.Pod
			}
		}
	}
	// Replace @ and . (dot) in usernames/service-names with - (dash) - kuberenetes is
	// not happy with @, minion wants to replace dot with dash, keep everyone happy
	// A Connector can login from same device to multiple pods. Currently, the connectid
	// is based on "tenant-bundleid" which is also treated as a service and registered
	// with Consul.
	data.Connectid = strings.ReplaceAll(uuid+"-"+data.Bid, "@", "-")
	data.Connectid = strings.ReplaceAll(data.Connectid, ".", "-")
	found := false
	for _, s := range data.Services {
		if s == data.Connectid {
			found = true
		}
	}
	if !found {
		data.Services = append(data.Services, data.Connectid)
	}

	appCltn := dbGetCollection(uuid, "NxtApps")
	if appCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	result := appCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Bid},
		bson.D{
			{"$set", bson.M{"name": data.Bundlename,
				"gateway": data.Gateway, "pod": data.Pod, "connectid": data.Connectid,
				"services": data.Services, "cpodrepl": data.CpodRepl}},
		},
		&opt,
	)
	if result.Err() != nil {
		return result.Err()
	}

	err := DBAddClusterBundle(uuid, data)
	if err != nil {
		return err
	}

	return nil
}

func DBFindBundle(tenant string, bundleid string) *Bundle {
	var app Bundle
	appCltn := dbGetCollection(tenant, "NxtApps")
	if appCltn == nil {
		return nil
	}
	err := appCltn.FindOne(
		context.TODO(),
		bson.M{"_id": bundleid},
	).Decode(&app)
	if err != nil {
		return nil
	}

	return &app
}

func DBFindAllBundlesStruct(tenant string) []Bundle {
	var tmp []Bundle
	var bundles []Bundle

	appCltn := dbGetCollection(tenant, "NxtApps")
	if appCltn == nil {
		return nil
	}
	cursor, err := appCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &tmp)
	if err != nil {
		return nil
	}

	hdockey := DBGetHdrKey("AppInfo")
	for _, b := range tmp {
		if b.Bid != hdockey {
			bundles = append(bundles, b)
		}
	}
	return bundles
}

func DBFindAllBundles(tenant string) []bson.M {
	var bundles []bson.M

	appCltn := dbGetCollection(tenant, "NxtApps")
	if appCltn == nil {
		return nil
	}
	cursor, err := appCltn.Find(context.TODO(), bson.M{})
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
			// Dont let UI/apis see the connectid added as a service
			svcs := bundles[i]["services"].(primitive.A)
			for k, s := range svcs {
				s = s.(string)
				if s == bundles[i]["connectid"] {
					l := len(svcs)
					svcs[k] = svcs[l-1]
					svcs = svcs[:l-1]
					break
				}
			}
			bundles[i]["services"] = svcs
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

func DBDelBundle(tenant string, bundleid string) error {
	var bun Bundle

	appCltn := dbGetCollection(tenant, "NxtApps")
	if appCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	err := appCltn.FindOne(context.TODO(), bson.M{"_id": bundleid}).Decode(&bun)
	if err != nil {
		return fmt.Errorf("Request to delete unknown bundle %s", bundleid)
	}
	_, err = appCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": bundleid},
	)
	if err != nil {
		return err
	}

	err = DBDelClusterBundle(tenant, bundleid)
	if err != nil {
		return err
	}

	return err
}

func dbAddBundleAttr(uuid string, bid string, Battr bson.M, replace bool) error {
	hdr := DBFindBundleAttrHdr(uuid)
	if hdr == nil {
		dhdr := DataHdr{Majver: 1, Minver: 0}
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
	appAttrCltn := dbGetCollection(uuid, "NxtAppAttr")
	if appAttrCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	if !replace {
		result := appAttrCltn.FindOneAndUpdate(
			context.TODO(),
			bson.M{"_id": bid},
			bson.D{{"$set", Battr}},
			&opt,
		)
		if result.Err() != nil {
			return result.Err()
		}
	} else {
		result, err := appAttrCltn.ReplaceOne(
			context.TODO(),
			bson.M{"_id": bid},
			Battr,
		)
		if err != nil {
			return err
		}
		if result.MatchedCount == 0 {
			return fmt.Errorf("Did not update any bundle")
		}
	}

	return DBAddBundleAttrHdr(uuid, hdr)
}

// Sample app-bundle attributes schema. It is transparent to the controller.
//type BundleAttr struct {
//	Bid         string             `bson:"_id" json:"bid"`
//	Tenant      string             `bson:"tenant" json:"tenant"`
//	Team        []string           `bson:"team" json:"team"`
//	Dept        []string           `bson:"dept" json:"dept"`
//	Contrib     int                `bson:"IC" json:"IC"`
//	Manager     int                `bson:"manager" json:"manager"`
//	Nonemployee string             `bson:"nonemployee" json:"nonemployee"`
//}

// This API will add/update a bundle attribute. If the data is nil,
// it just updates the "base" attributes and returns
func DBAddBundleAttr(uuid string, bid string, Battr bson.M) error {
	if Battr != nil {
		attrset := DBFindAllAttrSet(uuid)
		nattrs := 0
		for _, a := range attrset {
			if a.AppliesTo == "Bundles" {
				nattrs += 1
				found := false
				for k := range Battr {
					if k == a.Name {
						found = true
					}
				}
				if !found {
					return fmt.Errorf("All attributes defined in AttributeEditor needs to have some valid value provided", a.Name)
				}
			}
		}
	}
	if Battr == nil {
		attr := DBFindBundleAttr(uuid, bid)
		if attr != nil {
			Battr = *attr
			delete(Battr, "bid")
		} else {
			Battr = make(bson.M)
		}
	}
	dbBundle := DBFindBundle(uuid, bid)
	if dbBundle == nil {
		return fmt.Errorf("Cannot find bundle")
	}
	// Add the "base" attributes here which are like bundle name, pod etc..
	// These attributes will start with an underscore just to indicate that
	// these are not customer defined attributes. We will let customer know
	// about some attributes like _name which they can use in their policies
	Battr["_name"] = dbBundle.Bundlename
	Battr["_pod"] = fmt.Sprintf("cpod%d", dbBundle.Pod)
	Battr["_gateway"] = dbBundle.Gateway

	return dbAddBundleAttr(uuid, bid, Battr, false)
}

func DBFindBundleAttr(tenant string, bundleid string) *bson.M {
	var Battr bson.M
	appAttrCltn := dbGetCollection(tenant, "NxtAppAttr")
	if appAttrCltn == nil {
		return nil
	}
	err := appAttrCltn.FindOne(
		context.TODO(),
		bson.M{"_id": bundleid},
	).Decode(&Battr)
	if err != nil {
		return nil
	}
	Battr["bid"] = Battr["_id"]
	delete(Battr, "_id")
	return &Battr
}

func DBFindAllBundleAttrs(tenant string) []bson.M {
	var bundleAttrs []bson.M

	appAttrCltn := dbGetCollection(tenant, "NxtAppAttr")
	if appAttrCltn == nil {
		return nil
	}
	cursor, err := appAttrCltn.Find(context.TODO(), bson.M{})
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

func DBDelBundleAttr(tenant string, bundleid string) error {
	appAttrCltn := dbGetCollection(tenant, "NxtAppAttr")
	if appAttrCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	_, err := appAttrCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": bundleid},
	)

	return err
}

func DBDelAllBundlesOneAttr(tenant string, todel string) error {
	var attr bson.M

	appAttrCltn := dbGetCollection(tenant, "NxtAppAttr")
	if appAttrCltn == nil {
		return fmt.Errorf("Cant find user collection")
	}
	cursor, err := appAttrCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return err
	}
	defer cursor.Close(context.TODO())
	for cursor.Next(context.TODO()) {
		if err = cursor.Decode(&attr); err != nil {
			return err
		}
		delete(attr, todel)
		if err := dbAddBundleAttr(tenant, attr["_id"].(string), attr, true); err != nil {
			return err
		}
	}
	return nil
}

func DBAddAllBundlesOneAttr(tenant string, set AttrSet) error {
	var attr bson.M

	appAttrCltn := dbGetCollection(tenant, "NxtAppAttr")
	if appAttrCltn == nil {
		return fmt.Errorf("Cant find user collection")
	}
	cursor, err := appAttrCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return err
	}

	value := defaultType(set)

	defer cursor.Close(context.TODO())
	for cursor.Next(context.TODO()) {
		if err = cursor.Decode(&attr); err != nil {
			return err
		}
		attr[set.Name] = value
		if err := dbAddBundleAttr(tenant, attr["_id"].(string), attr, true); err != nil {
			return err
		}
	}
	return nil
}

//-------------------------------Host Attributes -------------------------

// This API will add/update a Host Attributes Header
func DBAddHostAttrHdr(uuid string, data *DataHdr) error {

	return DBAddCollectionHdr(uuid, data, "NxtHostAttr", "HostAttr")

}

func DBFindHostAttrHdr(tenant string) *DataHdr {

	return DBFindCollectionHdr(tenant, "NxtHostAttr", "HostAttr")
}

func DBDelHostAttrHdr(tenant string) error {

	return DBDelCollectionHdr(tenant, "NxtHostAttr", "HostAttr")
}

func DBFindHostAttr(tenant string, host string) *bson.M {
	var Hattr bson.M
	hostAttrCltn := dbGetCollection(tenant, "NxtHostAttr")
	if hostAttrCltn == nil {
		return nil
	}
	err := hostAttrCltn.FindOne(
		context.TODO(),
		bson.M{"_id": host},
	).Decode(&Hattr)
	if err != nil {
		return nil
	}

	Hattr["host"] = Hattr["_id"]
	delete(Hattr, "_id")
	return &Hattr
}

func DBFindAllHosts(tenant string) []string {
	var hostAttrs []bson.M
	hosts := []string{}

	hostAttrCltn := dbGetCollection(tenant, "NxtHostAttr")
	if hostAttrCltn == nil {
		return nil
	}
	cursor, err := hostAttrCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &hostAttrs)
	if err != nil {
		return nil
	}

	hdockey := DBGetHdrKey("HostAttr")
	for i := 0; i < len(hostAttrs); i++ {
		// Need to skip header doc
		host := fmt.Sprintf("%s", hostAttrs[i]["_id"])
		if host != hdockey {
			hosts = append(hosts, host)
		}
	}

	return hosts
}

func DBFindAllHostAttrs(tenant string) []bson.M {
	var hostAttrs []bson.M

	hostAttrCltn := dbGetCollection(tenant, "NxtHostAttr")
	if hostAttrCltn == nil {
		return nil
	}
	cursor, err := hostAttrCltn.Find(context.TODO(), bson.M{})
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

func dbAddHostAttr(uuid string, host string, Hattr bson.M, replace bool) error {
	hdr := DBFindHostAttrHdr(uuid)
	if hdr == nil {
		dhdr := DataHdr{Majver: 1, Minver: 0}
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
	hostAttrCltn := dbGetCollection(uuid, "NxtHostAttr")
	if hostAttrCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	if !replace {
		result := hostAttrCltn.FindOneAndUpdate(
			context.TODO(),
			bson.M{"_id": host},
			bson.D{{"$set", Hattr}},
			&opt,
		)
		if result.Err() != nil {
			return result.Err()

		}
	} else {
		result, err := hostAttrCltn.ReplaceOne(
			context.TODO(),
			bson.M{"_id": host},
			Hattr,
		)
		if err != nil {
			return err
		}
		if result.MatchedCount == 0 {
			return fmt.Errorf("Did not update any host")
		}
	}
	return DBAddHostAttrHdr(uuid, hdr)
}

// This API will add/update a host attributes doc
func DBAddHostAttr(uuid string, data []byte) error {
	var Hattr bson.M

	err := json.Unmarshal(data, &Hattr)
	if err != nil {
		return err
	}
	host := fmt.Sprintf("%s", Hattr["host"])
	delete(Hattr, "host")
	attrs := Hattr["routeattrs"].([]interface{})
	attrset := DBFindAllAttrSet(uuid)
	nattrs := 0
	for _, a := range attrset {
		if a.AppliesTo == "Hosts" {
			nattrs += 1
			for _, r := range attrs {
				found := false
				route := r.(map[string]interface{})
				for k := range route {
					if k == a.Name {
						found = true
					}
				}
				if !found {
					return fmt.Errorf("All attributes defined in AttributeEditor needs to have some valid value provided", a.Name)
				}
			}
		}
	}

	err = dbAddHostAttr(uuid, host, Hattr, false)
	if err != nil {
		return err
	}

	err = dbUpdateTenantDomains(uuid)
	if err != nil {
		return err
	}

	return nil
}

func DBDelHostAttr(tenant string, hostid string) error {
	hostAttrCltn := dbGetCollection(tenant, "NxtHostAttr")
	if hostAttrCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	_, err := hostAttrCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": hostid},
	)
	if err != nil {
		return err
	}
	err = dbUpdateTenantDomains(tenant)
	if err != nil {
		return err
	}

	return nil
}

func DBDelAllHostsOneAttr(tenant string, todel string) error {
	var attr bson.M

	hostAttrCltn := dbGetCollection(tenant, "NxtHostAttr")
	if hostAttrCltn == nil {
		return fmt.Errorf("Cant find user collection")
	}
	cursor, err := hostAttrCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return err
	}
	defer cursor.Close(context.TODO())
	for cursor.Next(context.TODO()) {
		if err = cursor.Decode(&attr); err != nil {
			return err
		}
		if attr["_id"].(string) != "Header" {
			attrs := attr["routeattrs"].(primitive.A)
			for _, r := range attrs {
				route := r.(primitive.M)
				delete(route, todel)
			}
			if err := dbAddHostAttr(tenant, attr["_id"].(string), attr, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func defaultType(set AttrSet) interface{} {
	if set.Type == "String" {
		if set.IsArray == "true" {
			return []string{""}
		} else {
			return ""
		}
	}
	if set.Type == "Number" {
		if set.IsArray == "true" {
			return []int{0}
		} else {
			return 0
		}
	}
	if set.Type == "Boolean" {
		if set.IsArray == "true" {
			return []bool{false}
		} else {
			return false
		}
	}
	if set.Type == "Date" {
		if set.IsArray == "true" {
			return []string{""}
		} else {
			return 0
		}
	}
	return 0
}

func DBAddAllHostsOneAttr(tenant string, set AttrSet) error {
	var attr bson.M

	hostAttrCltn := dbGetCollection(tenant, "NxtHostAttr")
	if hostAttrCltn == nil {
		return fmt.Errorf("Cant find user collection")
	}
	cursor, err := hostAttrCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return err
	}

	value := defaultType(set)

	defer cursor.Close(context.TODO())
	for cursor.Next(context.TODO()) {
		if err = cursor.Decode(&attr); err != nil {
			return err
		}
		if attr["_id"].(string) != "Header" {
			attrs := attr["routeattrs"].(primitive.A)
			for _, r := range attrs {
				route := r.(primitive.M)
				route[set.Name] = value
			}
			if err := dbAddHostAttr(tenant, attr["_id"].(string), attr, true); err != nil {
				return err
			}
		}
	}
	return nil
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
//	Tenant   string             `bson:"tenant" json:"tenant"`
//	Attrlist string             `bson:"attrlist" json:"attrlist"`
//}

func DBFindUserExtAttr(tenant string) *bson.M {
	var attr bson.M
	userAttrCltn := dbGetCollection(tenant, "NxtUserAttr")
	if userAttrCltn == nil {
		return nil
	}
	err := userAttrCltn.FindOne(
		context.TODO(),
		bson.M{"_id": "UserExtAttr"},
	).Decode(&attr)
	if err != nil {
		return nil
	}
	return &attr
}

// This API will add/update a user extended Attribute doc
func DBAddUserExtAttr(tenant string, data []byte) error {
	var UEAttr bson.M

	err := json.Unmarshal(data, &UEAttr)
	if err != nil {
		return err
	}

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
		bson.M{"_id": "UserExtAttr"},
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

func DBDelUserExtAttr(tenant string) error {
	userAttrCltn := dbGetCollection(tenant, "NxtUserAttr")
	if userAttrCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	_, err := userAttrCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": "UserExtAttr"},
	)

	return err
}

//--------------------------------Agent Onboarding Log-------------------------------------

type OnboardLog struct {
	Uid       string `json:"uid" bson:"_id"`
	Gw        string `json:"gw" bson:"gw"`
	Connectid string `json:"connectid" bson:"connectid"`
	OnbTime   string `json:"onbtime" bson:"onbtime"` // Time as a RFC3339 format json string
	Count     int    `json:"count" bson:"count"`
	PrevTime  string `json:"prevtime" bson:"prevtime"`
}

// This API will add a new onboarding log entry
func DBAddOnboardLog(tenant string, data *OnboardLog) error {

	data.Count = 1
	data.PrevTime = ""
	onbl := DBFindOnboardLog(tenant, data.Uid)
	if onbl != nil {
		data.Count = onbl.Count + 1
		data.PrevTime = onbl.OnbTime
	}
	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	onboardCltn := dbGetCollection(tenant, "NxtOnboardLog")
	if onboardCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	err := onboardCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Uid},
		bson.D{
			{"$set", bson.M{"gw": data.Gw,
				"connectid": data.Connectid, "onbtime": data.OnbTime,
				"count": data.Count, "prevtime": data.PrevTime}},
		},
		&opt,
	)

	if err.Err() != nil {
		return err.Err()
	}
	return nil
}

// This API will delete a gateway if its not in use by any tenants
func DBDelOnboardLog(tenant string, name string) error {

	ol := DBFindOnboardLog(tenant, name)
	if ol == nil {
		// Log entry doesn't exist. Return silently
		return nil
	}
	onboardCltn := dbGetCollection(tenant, "NxtOnboardLog")
	if onboardCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	_, err := onboardCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": name},
	)
	return err
}

func DBFindOnboardLog(tenant string, name string) *OnboardLog {
	var ol OnboardLog
	onboardCltn := dbGetCollection(tenant, "NxtOnboardLog")
	if onboardCltn == nil {
		return nil
	}
	err := onboardCltn.FindOne(
		context.TODO(),
		bson.M{"_id": name},
	).Decode(&ol)
	if err != nil {
		return nil
	}
	return &ol
}
