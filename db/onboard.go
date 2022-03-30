package db

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang/glog"
	"github.com/sethvargo/go-password/password"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const HDRKEY = "Header"

var uattrLock sync.RWMutex
var battrLock sync.RWMutex
var hattrLock sync.RWMutex

type Signup struct {
	Tenant string `json:"tenant" bson:"tenant"`
	Email  string `json:"email" bson:"email"`
	IsMsp  bool   `json:"ismsp"`
}

type CustomClaims struct {
	Tenant   string `json:"tenant"`
	Username string `json:"sub"`
	Secret   string `json:"secret"`
	Usertype string `json:"usertype"`
	Name     string `json:"name"`
	Time     uint64 `json:"time"`
	jwt.StandardClaims
}

func VerifyMyJwt(r *http.Request, bearerToken string) *context.Context {
	claims := GetMyJwt(bearerToken)
	if claims == nil {
		return nil
	}
	ctx := context.WithValue(r.Context(), "user-tenant", claims.Tenant)
	ctx = context.WithValue(ctx, "userid", claims.Username)
	ctx = context.WithValue(ctx, "usertype", claims.Usertype)
	ctx = context.WithValue(ctx, "secret", claims.Secret)

	user := DBFindUser(claims.Tenant, claims.Username)
	if user != nil {
		found := false
		for _, k := range user.Keys {
			if k.Name == claims.Name {
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}

	return &ctx
}

func GetMyJwt(bearerToken string) *CustomClaims {
	token, err := jwt.ParseWithClaims(
		bearerToken,
		&CustomClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte("TODONeedSecureNextensioSecret"), nil
		},
	)
	if err != nil {
		fmt.Println("My claim not verified", err)
		return nil
	}
	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		fmt.Println("couldn't parse My claims")
		return nil
	}
	return claims
}

func GenMyJwt(name string, tenant string, username string, usertype string) (string, error) {
	secret, err := password.Generate(64, 10, 10, false, false)
	if err != nil {
		return "", err
	}
	claims := CustomClaims{
		Tenant:   tenant,
		Username: username,
		Usertype: usertype,
		Secret:   secret,
		Name:     name,
		Time:     uint64(time.Now().Unix()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte("TODONeedSecureNextensioSecret"))
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

//TODO: The usages of "FindAllXYZ" has to be audited and modified to a more appropriate form,
//it will be a killer as we scale to thousands of users / tenants etc.. And we will need the
//UI also to be modified to not use FindAllXYZ and instead find within a given range etc.

func delEmpty(s []string) []string {
	var r []string
	for _, str := range s {
		if strings.TrimSpace(str) != "" {
			r = append(r, strings.TrimSpace(str))
		}
	}
	return r
}

// Remove port number from any app url. If this results in duplicate
// urls, remove duplicate. Do this when sending domains to Agent.
// Agent should not get a domain with a port #
func ProcessDomains(s []Domain) []Domain {
	var r []Domain
	var svcs map[string]bool
	svcs = make(map[string]bool)
	for _, str := range s {
		if strings.TrimSpace(str.Name) != "" {
			splitstr := strings.Split(str.Name, ":")
			svcs[splitstr[0]] = true
		}
	}
	for svc, _ := range svcs {
		r = append(r, Domain{Name: svc})
	}
	return r
}

// NOTE: The bson decoder will not work if the structure field names dont start with upper case
type Keepalive struct {
	Gateway uint   `json:"gateway" bson:"gateway"`
	Device  string `json:"device" bson:"device"`
	Version string `json:"version" bson:"version"`
	Source  string `json:"source" bson:"source"`
	Seen    int64  `bson:"seen"`
}

type IDP struct {
	Provider string `json:"provider" bson:"provider"`
	Name     string `json:"name" bson:"name"`
	Idp      string `json:"idp" bson:"idp"`
	Policy   string `json:"policy" bson:"policy"`
	Domain   string `json:"domain" bson:"domain"`
	Group    string `json:"group" bson:"group"`
	Auth     string `json:"auth" bson:"auth"`
	Jwks     string `json:"jwks" bson:"jwks"`
	Token    string `json:"token" bson:"token"`
	Issuer   string `json:"issuer" bson:"issuer"`
	Sso      string `json:"sso" bson:"sso"`
	Audience string `json:"audience" bson:"audience"`
	Client   string `json:"client" bson:"client"`
	Secret   string `json:"secret" bson:"secret"`
	Cert     string `json:"cert" bson:"cert"`
	Keyid    string `json:"keyid" bson:"keyid"`
}

// NOTE: The bson decoder will not work if the structure field names dont start with upper case
type TenantJson struct {
	ID        string  `json:"_id"`
	Name      *string `json:"name"`
	Group     string  `json:"group" bson:"group"`
	EasyMode  *bool   `json:"easymode"`
	IsMsp     bool    `json:"ismsp"`
	IsManaged bool    `json:"ismanaged"`
}

// Tenant Type : "self-managed" | "MSP" | "MSP-managed"
// If MSP-managed, MspID will contain tenant ID of MSP
// If MSP, MgdTenants will contain tenant IDs of MSP-managed tenants
// A self-managed tenant should not have any values in MspID or MgdTenants
type Tenant struct {
	ID            string   `json:"_id" bson:"_id"`
	Name          string   `json:"name" bson:"name"`
	Group         string   `json:"group" bson:"group"`
	Domains       []Domain `json:"domains" bson:"domains"`
	EasyMode      bool     `json:"easymode" bson:"easymode"`
	SplitTunnel   bool     `json:"splittunnel" bson:"splittunnel"`
	ConfigVersion uint64   `json:"cfgvn" bson:"cfgvn"`
	Idps          []IDP    `json:"idps" bson:"idps"`
	AdmGroups     []string `json:"admgroups" bson:"admgroups"`
	Type          string   `json:"type" bson:"type"`
	MspID         string   `json:"mspid" bson:"mspid"`
	MgdTenants    []string `json:"mgdtenants" bson:"mgdtenants"`
	OwnedEmails   []string `json:"ownedemails" bson:"ownedemails"`
}

type Domain struct {
	Name string `json:"name" bson:"name"`
}

func DBaddTenantIdp(tenant *Tenant, new IDP) error {
	found := false
	for i, d := range tenant.Idps {
		if d.Name == new.Name {
			tenant.Idps[i] = new
			found = true
		}
	}
	if !found {
		tenant.Idps = append(tenant.Idps, new)
	}
	return dbUpdateTenant(tenant)
}

func DBdelTenantIDP(tenant *Tenant, name string) error {
	for i, d := range tenant.Idps {
		if d.Name == name {
			tenant.Idps = append(tenant.Idps[:i], tenant.Idps[i+1:]...)
			break
		}
	}
	return dbUpdateTenant(tenant)
}

func dbaddTenantDomain(uuid string, host string) error {
	tenant := DBFindTenant(uuid)
	if tenant == nil {
		return errors.New("Cant find tenant")
	}
	domain := Domain{
		Name: host,
	}
	tenant.Domains = append(tenant.Domains, domain)
	// Need to update agents because the tenant domain has changed.
	tenant.ConfigVersion = uint64(time.Now().Unix())
	return dbUpdateTenant(tenant)
}

func dbdelTenantDomain(uuid string, host string) error {
	tenant := DBFindTenant(uuid)
	if tenant == nil {
		return errors.New("Cant find tenant")
	}
	for i, d := range tenant.Domains {
		if d.Name == host {
			tenant.Domains = append(tenant.Domains[:i], tenant.Domains[i+1:]...)
			break
		}
	}
	// Need to update agents because the tenant domain has changed.
	tenant.ConfigVersion = uint64(time.Now().Unix())
	return dbUpdateTenant(tenant)
}

type AdminGroups struct {
	Tenant    string   `json:"_id" bson:"_id"`
	AdmGroups []string `json:"admgroups" bson:"admgroups"` // array of group names
}

func DBFindTenantAdminGroups(id string) *[]string {
	var admingrps AdminGroups
	err := tenantCltn.FindOne(
		context.TODO(),
		bson.M{"_id": id},
	).Decode(&admingrps)
	if err != nil {
		glog.Errorf("FindAdminGroups: Error - %v", err)
		return nil
	}
	return &admingrps.AdmGroups
}

func DBAddTenantAdminGroup(uuid string, grp string) error {

	if grp == "" {
		return errors.New("AddAdminGroup: Group not specified")
	} else {
		var isNameValid = regexp.MustCompile(`^[a-zA-Z]*$`).MatchString
		if !isNameValid(grp) {
			return errors.New("AddAdminGroup: Invalid group name. Name should be any of `[a-zA-Z]`")
		}
	}
	tenant := DBFindTenant(uuid)
	if tenant == nil {
		return errors.New("AddAdminGroup: Could not find tenant")
	}
	found := false
	for _, g := range tenant.AdmGroups {
		if g == grp {
			found = true
			break
		}
	}
	if !found {
		tenant.AdmGroups = append(tenant.AdmGroups, grp)
		return dbUpdateTenant(tenant)
	}
	return errors.New("AddAdminGroup: Admin group " + grp + " already exists")
}

func DBDelTenantAdminGroup(uuid string, grp string) error {

	if grp == "" {
		return errors.New("DelAdminGroup: Group not specified")
	}
	tenant := DBFindTenant(uuid)
	if tenant == nil {
		return errors.New("DelAdminGroup: Cant find tenant")
	}
	for i, g := range tenant.AdmGroups {
		if g == grp {
			tenant.AdmGroups = append(tenant.AdmGroups[:i], tenant.AdmGroups[i+1:]...)
			return dbUpdateTenant(tenant)
		}
	}
	return errors.New("DelAdminGroup: Admin group " + grp + " not found")
}

// Update type of tenant. Can be done by superadmin only.
func DBUpdTenantType(tnt string, typ string) error {

	tenant := DBFindTenant(tnt)
	if tenant == nil {
		return errors.New("Cant find tenant")
	}
	tenant.Type = typ
	return dbUpdateTenant(tenant)
}

// Add a managed tenant to MSP. Can be done by superadmin only.
func DBAddManagedTenant(tnt string, mgdtnt string) error {

	tenant := DBFindTenant(tnt)
	if tenant == nil {
		return errors.New("Cant find MSP tenant")
	}
	mgdtenant := DBFindTenant(mgdtnt)
	if mgdtenant == nil {
		return errors.New("Cant find managed tenant")
	}
	if tenant.Type != "MSP" {
		return errors.New("Tenant is not an MSP")
	}
	if mgdtenant.Type != "MSP-managed" {
		return errors.New("Target Tenant is not a managed tenant")
	}
	mgdtenant.MspID = tnt
	// Add managed tenant ID to MSP's list of managed tenants
	// Update both tenants
	found := false
	for _, tid := range tenant.MgdTenants {
		if tid == mgdtenant.ID {
			found = true
			break
		}
	}
	var err error
	if !found {
		tenant.MgdTenants = append(tenant.MgdTenants, mgdtenant.ID)
		err = dbUpdateTenant(tenant)
		if err != nil {
			return errors.New("MSP Tenant could not be updated")
		}
	}
	return dbUpdateTenant(mgdtenant)
}

// Delete a managed tenant from MSP. Can be done by superadmin only.
func DBDelManagedTenant(tnt string, mgdtnt string) error {

	tenant := DBFindTenant(tnt)
	if tenant == nil {
		return errors.New("Cant find MSP tenant")
	}
	mgdtenant := DBFindTenant(mgdtnt)
	if mgdtenant == nil {
		return errors.New("Cant find managed tenant")
	}
	if tenant.Type != "MSP" {
		return errors.New("Tenant is not an MSP")
	}
	if mgdtenant.Type != "MSP-managed" {
		return errors.New("Target Tenant is not a managed tenant")
	}
	// Remove managed tenant ID from MSP's list of managed tenants
	// Update both tenants
	found := false
	for i, tid := range tenant.MgdTenants {
		if tid == mgdtenant.ID {
			found = true
			tenant.MgdTenants = append(tenant.MgdTenants[:i], tenant.MgdTenants[i+1:]...)
			break
		}
	}
	var err error
	if mgdtenant.MspID == tnt {
		mgdtenant.MspID = ""
		err = dbUpdateTenant(mgdtenant)
		if err != nil {
			return err
		}
	}
	if found {
		return dbUpdateTenant(tenant)
	}
	return nil
}

// Get managed tenants for an MSP.
func DBGetManagedTenants(tnt string) *[]string {
	var mgdt []string

	tenant := DBFindTenant(tnt)
	if tenant == nil {
		return nil
	}
	if tenant.Type != "MSP" {
		return nil
	}
	for _, tid := range tenant.MgdTenants {
		mgdt = append(mgdt, tid)
	}
	return &mgdt
}

func dbUpdateTenant(tenant *Tenant) error {
	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}

	err := tenantCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": tenant.ID},
		bson.D{
			{"$set", *tenant},
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

func dbTenantUpdateJson(tenant *Tenant, data *TenantJson) *Tenant {
	if tenant == nil {
		t := Tenant{}
		t.ID = data.ID
		if data.Name == nil {
			t.Name = data.ID
		} else {
			t.Name = *data.Name
		}
		if data.EasyMode == nil {
			t.EasyMode = true
		} else {
			t.EasyMode = *data.EasyMode
		}
		t.Group = data.Group
		t.Domains = []Domain{}
		t.OwnedEmails = []string{}
		if data.IsMsp {
			t.Type = "MSP"
		} else if data.IsManaged {
			t.Type = "MSP-managed"
		} else {
			t.Type = "self-managed"
		}
		return &t
	} else {
		if data.Name != nil {
			tenant.Name = *data.Name
		}
		if data.EasyMode != nil {
			tenant.EasyMode = *data.EasyMode
		}
		return tenant
	}
}

// This API will add a new tenant or update a tenant if it already exists.
// Tenant additions are now not dependent on gateways/clusters. After adding
// the tenant, we link the tenant to one or more gateways/clusters via the
// TenantCluster configuration. This can be done incrementally. Tenants can be
// in different clusters using different number of minion allocations in each
// cluster.
func DBAddTenant(data *TenantJson, admin string) error {

	if !validateTenant(data.ID) {
		return errors.New("invalid tenant id")
	}

	// See if tenant doc exists, if so inherit some values, if not create new tenant
	tdoc := DBFindTenant(data.ID)
	tenant := dbTenantUpdateJson(tdoc, data)

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}

	err := tenantCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.ID},
		bson.D{
			{"$set", tenant},
		},
		&opt,
	)
	if err.Err() != nil {
		return err.Err()
	}

	if tdoc == nil {
		// New tenant being added, so create logical DB for tenant
		// and add header docs for all attribute collections of tenant
		dbAddTenantDB(data.ID)
		DBAddTenantCollectionHdrs(data.ID, admin)
	}

	return nil
}

func DBAddTenantCollectionHdrs(tenant string, admin string) {
	hdr := DataHdr{Majver: 1, Minver: 0}

	_ = dbAddUserInfoHdr(tenant, admin, &hdr)
	_ = dbAddUserAttrHdr(tenant, admin, &hdr)
	_ = dbAddBundleInfoHdr(tenant, admin, &hdr)
	_ = dbAddBundleAttrHdr(tenant, admin, &hdr)
	_ = dbAddHostAttrHdr(tenant, admin, &hdr)
	_ = dbAddTraceRequestsHdr(tenant, admin, &hdr)
	// TenantCluster collection does not have a header doc for now
}

func DBDelTenantCollectionHdrs(tenant string) {

	_ = dbDelUserInfoHdr(tenant)
	_ = dbDelUserAttrHdr(tenant)
	_ = dbDelBundleInfoHdr(tenant)
	_ = dbDelBundleAttrHdr(tenant)
	_ = dbDelHostAttrHdr(tenant)
	_ = dbDelTraceRequestsHdr(tenant)
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

func DBFindAllTenants() ([]Tenant, error) {
	var tenants []Tenant

	cursor, err := tenantCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil, err
	}
	err = cursor.All(context.TODO(), &tenants)
	if err != nil {
		return nil, err
	}

	return tenants, nil
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

func DBTenantInAnyCluster(tenant string) (error, bool) {
	err, gws := DBFindAllGatewaysForTenant(tenant)
	if err != nil {
		return err, false
	}
	for _, gw := range gws {
		cltenantClnt := ClusterGetCollection(DBGetClusterName(gw.Name), "NxtTenants")
		var result bson.M
		err := cltenantClnt.FindOne(
			context.TODO(),
			bson.M{"_id": tenant},
		).Decode(&result)
		if err == nil {
			return nil, true
		}
		if err != mongo.ErrNoDocuments {
			return err, false
		}
	}
	return nil, false
}

func DBDelTenant(id string) error {
	err, inuse := DBTenantInAnyCluster(id)
	if err != nil {
		return err
	}
	if inuse {
		return errors.New("Tenant assigned to clusters - cannot delete")
	}
	err = DBDelTenantDocOnly(id)
	if err != nil {
		return err
	}

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
			// Default image
			data.Image = "registry.gitlab.com/nextensio/cluster/minion:production"
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
	if err := DBSetGlboalCfgVn(); err != nil {
		return err
	}
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
	if err := DBSetGlboalCfgVn(); err != nil {
		return err
	}
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

//---------------------------Version functions---------------------------

// NOTE: The bson decoder will not work if the structure field names dont start with upper case
type GlobalVersions struct {
	ConfigVersion uint64 `json:"version" bson:"version"`
}

// This API will add a new certificate or update a certificate if it already exists
func DBSetGlboalCfgVn() error {

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := versionCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": "cfgvn"},
		bson.D{
			{"$set", bson.M{"_id": "cfgvn", "version": uint64(time.Now().Unix())}},
		},
		&opt,
	)

	if err.Err() != nil {
		return err.Err()
	}
	return nil
}

func DBGetGlboalCfgVn() uint64 {
	var vn GlobalVersions
	err := versionCltn.FindOne(
		context.TODO(),
		bson.M{"_id": "cfgvn"},
	).Decode(&vn)
	if err != nil {
		fmt.Println("Get global version failed", err)
		return 0
	}
	return vn.ConfigVersion
}

//---------------------------Clientid functions---------------------------

// NOTE: The bson decoder will not work if the structure field names dont start with upper case
type ClientId struct {
	Clientid string `json:"clientid" bson:"clientid"`
}

// This API will add a new certificate or update a certificate if it already exists
func DBAddClientId(data *ClientId) error {

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := clientIdCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": "SPA"},
		bson.D{
			{"$set", bson.M{"_id": "SPA", "clientid": data.Clientid}},
		},
		&opt,
	)

	if err.Err() != nil {
		return err.Err()
	}
	return nil
}

func DBFindClientId() *ClientId {
	var clientid ClientId
	err := clientIdCltn.FindOne(
		context.TODO(),
		bson.M{"_id": "SPA"},
	).Decode(&clientid)
	if err != nil {
		return nil
	}
	return &clientid
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

	e, gws := DBFindAllGateways()
	if e != nil {
		return e
	}
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

	// TODO: Right now we say every gateway talks to every other gateway, but eventually
	// that might not be the case. Like gateways in US might not talk to the ones in europe
	// etc.., we will need some way to figure that out and then modify this code
	remotes := []string{}
	for _, gw := range gws {
		if gw.Name != data.Name {
			remotes = append(remotes, DBGetClusterName(gw.Name))
		}
	}
	e = DBAddClusterGateway(data, remotes)
	if e != nil {
		return e
	}
	for _, gw := range gws {
		if gw.Name != data.Name {
			e = DBAddDelClusterGatewayRemote(gw.Name, data.Name, true)
			if e != nil {
				return e
			}
		}
	}

	// TODO: This is not scaleable and needs to change, but initially at least till our
	// solution gets customer acceptance, we dont want them to know anything about our
	// gateways and stuff, we just want to keep it simple for them. So we just want to assign
	// ALL gateways to ALL tenants. Obviously that wont work in the long run for the same
	// reason mentioned in the TODO above. So we will have to come back and revisit this
	tenants, e := DBFindAllTenants()
	if e != nil {
		return e
	}
	for _, t := range tenants {
		tcl := TenantCluster{Gateway: data.Name, Image: "", ApodSets: 1, ApodRepl: 1}
		e = DBAddTenantCluster(t.ID, &tcl)
		if e != nil {
			// Well, try to cleanup all that we added and get out. The cleanup can fail,
			// in which case
			for _, t := range tenants {
				ec := DBDelTenantCluster(t.ID, DBGetClusterName(data.Name))
				if ec != nil {
					fmt.Println("Error cleaning up failed tenant cluster", e, t.ID, data.Name)
				}
			}
			return e
		}
	}

	return nil
}

// This API will delete a gateway if its not in use by any tenants
func DBDelGateway(name string) error {

	e, all := DBFindAllGateways()
	if e != nil {
		return e
	}

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

	e = DBDelClusterGateway(name)
	if e != nil {
		return e
	}
	for _, a := range all {
		if a.Name != gw.Name {
			e = DBAddDelClusterGatewayRemote(a.Name, gw.Name, false)
			if e != nil {
				return e
			}
		}
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
	Group     string `bson:"group" json:"group"`
}

func DBAddAttrSet(tenant string, admin string, group string, s AttrSet, rsrvd bool) error {
	var attrdef AttrSet

	Cltn := dbGetCollection(tenant, "NxtAttrSet")
	if Cltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	uscore := strings.HasPrefix(s.Name, "_")
	afound := true
	switch s.AppliesTo {
	case "Users":
		uattrLock.Lock()
		defer uattrLock.Unlock()
	case "Hosts":
		hattrLock.Lock()
		defer hattrLock.Unlock()
	case "Bundles":
		battrLock.Lock()
		defer battrLock.Unlock()
	default:
		return fmt.Errorf("Attribute has invalid AppliesTo " + s.AppliesTo)
	}
	err := Cltn.FindOne(context.TODO(), bson.M{"_id": s.Name + ":" + s.AppliesTo}).Decode(&attrdef)
	if err != nil {
		// This attribute is not defined, so validate input
		afound = false
		if rsrvd && !uscore {
			return fmt.Errorf("Attribute name does not conform to reserved attributes")
		}
		if !rsrvd && uscore {
			return fmt.Errorf("Attribute name indicates reserved attribute")
		}

		// Validate some fields in the AttrSet
		switch s.Type {
		case "String":
		case "Number":
		case "Boolean":
			if s.IsArray == "true" {
				return fmt.Errorf("Boolean type attribute cannot be an array")
			}
		case "Date":
		default:
			return fmt.Errorf("Attribute has invalid type " + s.Type)
		}
		switch s.IsArray {
		case "true":
		case "false":
		default:
			return fmt.Errorf("Attribute has invalid isArray " + s.IsArray)
		}
	}
	if afound {
		// Attribute is already defined, ensure that its type is not
		// being changed in any way.
		if attrdef.Type != s.Type || attrdef.IsArray != s.IsArray {
			return fmt.Errorf("Attribute is defined. Its type cannot be changed")
		}
		if attrdef.Group == group {
			// If group is not changing, nothing has changed in the
			// attribute definition, so return without fuss.
			return nil
		}
		// Only Group field is changing. Allow this only for a rsrvd attribute,
		// for eg., the device attributes. If not reserved, return error.
		if !uscore {
			return fmt.Errorf("To change attribute group, ensure it is not in use, then delete and recreate it")
		}
		glog.Infof("AddAttrSet: Updating %s attribute %s from group %s to %s", s.AppliesTo, s.Name, attrdef.Group, group)
	}
	s.Group = group

	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	ferr := Cltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": s.Name + ":" + s.AppliesTo},
		bson.D{
			{"$set", bson.M{"name": s.Name, "appliesTo": s.AppliesTo,
				"type": s.Type, "isArray": s.IsArray, "group": s.Group}},
		},
		&opt,
	)
	if ferr.Err() != nil {
		glog.Errorf("AttrSet: Add/update error - %v", ferr)
		return ferr.Err()
	}
	if uscore || afound {
		// If attribute exists, no need to add it again to docs in the attribute
		// collection involved.
		// Also, if it's a reserved attribute, don't add it to any attribute
		// collection. Reserved attribute names start with _.
		return nil
	}
	glog.Infof("AddAttrSet: Added %s attribute %s in group %s", s.AppliesTo, s.Name, s.Group)
	switch s.AppliesTo {
	case "Hosts":
		if err := DBAddAllHostsOneAttr(tenant, admin, s); err != nil {
			return err
		}
	case "Users":
		if err := DBAddAllUsersOneAttr(tenant, admin, s); err != nil {
			return err
		}
	case "Bundles":
		if err := DBAddAllBundlesOneAttr(tenant, admin, s); err != nil {
			return err
		}
	}
	return nil
}

// Delete an attribute definition. At a minimum, the name and appliesTo fields
// are required. System attributes cannot be deleted via the api, only from
// within the system.
func DBDelAttrSet(tenant string, admin string, group string, set AttrSet, apicall bool) error {

	sysattr := strings.HasPrefix(set.Name, "_")
	if apicall && sysattr {
		return fmt.Errorf("Cannot delete a system attribute via the api")
	}
	Cltn := dbGetCollection(tenant, "NxtAttrSet")
	if Cltn == nil {
		return fmt.Errorf("Unknown Collection")
	}

	switch set.AppliesTo {
	case "Hosts":
		hattrLock.Lock()
		defer hattrLock.Unlock()
	case "Users":
		uattrLock.Lock()
		defer uattrLock.Unlock()
	case "Bundles":
		battrLock.Lock()
		defer battrLock.Unlock()
	}
	var curSet AttrSet
	err := Cltn.FindOne(context.TODO(), bson.M{"_id": set.Name + ":" + set.AppliesTo}).Decode(&curSet)
	if err != nil {
		return err
	}
	if apicall {
		// Check group privilege if it's an api call. If an internal delete to
		// clean up, disregard group.
		if group != "admin" && group != "superadmin" {
			// If user trying to delete attribute is a group admin, ensure the
			// group admin owns the attribute
			if curSet.Group != "" && curSet.Group != group {
				return fmt.Errorf("Admin group not matching attribute group")
			}
		}
	}
	if !sysattr {
		// Do not try to remove system attributes from any attribute collection.
		// They don't exist there.
		switch set.AppliesTo {
		case "Hosts":
			if err := DBDelAllHostsOneAttr(tenant, admin, set.Name); err != nil {
				return err
			}
		case "Users":
			// First check if attribute is being used in any rules (in Easy mode)
			tnt := DBFindTenant(tenant)
			if tnt == nil {
				return fmt.Errorf("Tenant " + tenant + " not found")
			}
			if tnt.EasyMode && DBRulesContainAttribute(tenant, set.Name) {
				return fmt.Errorf("Rules contain attribute " + set.Name + " being deleted")
			}
			if err := DBDelAllUsersOneAttr(tenant, admin, set.Name); err != nil {
				return err
			}
		case "Bundles":
			if err := DBDelAllBundlesOneAttr(tenant, admin, set.Name); err != nil {
				return err
			}
		}
	}
	_, err = Cltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": set.Name + ":" + set.AppliesTo},
	)
	if err != nil {
		return err
	}

	return nil
}

func DBFindSpecificAttrSet(tenant string, atyp string, group string) []AttrSet {
	var set []AttrSet
	var err error
	var cursor *mongo.Cursor

	attrSetCltn := dbGetCollection(tenant, "NxtAttrSet")
	if attrSetCltn == nil {
		glog.Errorf("AttrSet: Could not find AttrSet collection")
		return nil
	}

	switch atyp {
	case "Users":
	case "Hosts":
	case "Bundles":
	case "all":
	default:
		glog.Errorf("Attribute has invalid AppliesTo " + atyp)
		return nil
	}
	if group == "all" {
		if atyp == "all" {
			cursor, err = attrSetCltn.Find(context.TODO(), bson.M{})
		} else {
			cursor, err = attrSetCltn.Find(context.TODO(), bson.M{"appliesTo": atyp})
		}
	} else {
		if atyp == "all" {
			cursor, err = attrSetCltn.Find(context.TODO(), bson.M{"group": group})
		} else {
			cursor, err = attrSetCltn.Find(context.TODO(), bson.M{"appliesTo": atyp, "group": group})
		}
	}
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
	ID       string `bson:"_id" json:"ID"`
	Majver   int    `bson:"majver" json:"majver"`
	Minver   int    `bson:"minver" json:"minver"`
	ChangeBy string `bson:"changeby" json:"changeby"`
	ChangeAt string `bson:"changeat" json:"changeat"`
}

func DBGetHdrKey(val string) string {
	return HDRKEY // common name for all header docs
}

func dbAddCollectionHdr(uuid string, admin string, data *DataHdr, htype string, hkey string) error {
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
	timenow := fmt.Sprintf("%s", time.Now().Format(time.RFC1123))
	hdockey := DBGetHdrKey(hkey)
	err := Cltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": hdockey},
		bson.D{
			{"$set", bson.M{"minver": data.Minver, "majver": data.Majver,
				"changeby": admin, "changeat": timenow}},
		},
		&opt,
	)
	return err.Err()
}

func dbUpdateCollectionHdr(tenant string, admin string, htype string, hkey string) error {
	hdr := dbFindCollectionHdr(tenant, htype, hkey)
	if hdr == nil {
		return nil //TODO return error ?
	}
	hdr.Minver += 1
	return dbAddCollectionHdr(tenant, admin, hdr, htype, hkey)
}

func dbFindCollectionHdr(tenant string, htype string, hkey string) *DataHdr {
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

func dbDelCollectionHdr(tenant string, htype string, hkey string) error {

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
func dbAddUserInfoHdr(uuid string, admin string, data *DataHdr) error {

	return dbAddCollectionHdr(uuid, admin, data, "NxtUsers", "UserInfo")
}

// This API will update a user Info Header
func dbUpdateUserInfoHdr(uuid string, admin string) error {

	return dbUpdateCollectionHdr(uuid, admin, "NxtUsers", "UserInfo")
}

func DBFindUserInfoHdr(tenant string) *DataHdr {

	return dbFindCollectionHdr(tenant, "NxtUsers", "UserInfo")
}

func dbDelUserInfoHdr(tenant string) error {

	return dbDelCollectionHdr(tenant, "NxtUsers", "UserInfo")
}

// This API will add a user Attribute Header
func dbAddUserAttrHdr(uuid string, admin string, data *DataHdr) error {

	return dbAddCollectionHdr(uuid, admin, data, "NxtUserAttr", "UserAttr")
}

// This API will update a user Attribute Header
func dbUpdateUserAttrHdr(uuid string, admin string) error {

	return dbUpdateCollectionHdr(uuid, admin, "NxtUserAttr", "UserAttr")
}

func DBFindUserAttrHdr(tenant string) *DataHdr {

	return dbFindCollectionHdr(tenant, "NxtUserAttr", "UserAttr")
}

func dbDelUserAttrHdr(tenant string) error {
	return dbDelCollectionHdr(tenant, "NxtUserAttr", "UserAttr")
}

type UserKeyJson struct {
	Name string `json:"name" bson:"name"`
}

type UserKey struct {
	Name string `json:"name" bson:"name"`
}

// The Pod here indicates the "pod set" that this user should
// connect to, each pod set has its own number of replicas etc..
type User struct {
	Uid       string      `json:"uid" bson:"_id"`
	Username  string      `json:"name" bson:"name"`
	Email     string      `json:"email" bson:"email"`
	Gateway   string      `json:"gateway" bson:"gateway"`
	Usertype  string      `json:"usertype" bson:"usertype"`
	Pod       int         `json:"pod" bson:"pod"`
	Connectid string      `json:"connectid" bson:"connectid"`
	Services  []string    `json:"services" bson:"services"`
	Keepalive []Keepalive `json:"keepalive" bson:"keepalive"`
	Keys      []UserKey   `json:"keys" bson:"keys"`
}

// This API will add a new user API key
func DBAddUserKey(uuid string, userid string, usertype string, key *UserKeyJson) (string, error) {

	key.Name = strings.TrimSpace(key.Name)
	if key.Name == "" {
		return "", fmt.Errorf("Need non empty key name")
	}
	tenant := DBFindTenant(uuid)
	if tenant == nil {
		return "", fmt.Errorf("Unknown tenant")
	}
	user := DBFindUser(uuid, userid)
	if user == nil {
		return "", fmt.Errorf("User not found")
	}
	for _, k := range user.Keys {
		if k.Name == key.Name {
			return "", fmt.Errorf("Key already exists")
		}
	}
	token, err := GenMyJwt(key.Name, uuid, userid, usertype)
	if err != nil {
		return "", err
	}
	user.Keys = append(user.Keys, UserKey{Name: key.Name})

	userCltn := dbGetCollection(uuid, "NxtUsers")
	if userCltn == nil {
		return "", fmt.Errorf("Unknown Collection")
	}
	upsert := false
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	result := userCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": userid},
		bson.D{
			{"$set", bson.M{"keys": user.Keys}},
		},
		&opt,
	)

	if result.Err() != nil {
		return "", result.Err()
	}

	return token, nil
}

// This API will add a new user API key
func DBDelUserKey(uuid string, userid string, key string) error {

	tenant := DBFindTenant(uuid)
	if tenant == nil {
		return fmt.Errorf("Unknown tenant")
	}
	user := DBFindUser(uuid, userid)
	if user == nil {
		return fmt.Errorf("User not found")
	}
	found := false
	index := 0
	for i, k := range user.Keys {
		if k.Name == key {
			found = true
			index = i
			break
		}
	}
	if !found {
		return fmt.Errorf("Key not found")
	}
	user.Keys = append(user.Keys[:index], user.Keys[index+1:]...)

	userCltn := dbGetCollection(uuid, "NxtUsers")
	if userCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	upsert := false
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	result := userCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": userid},
		bson.D{
			{"$set", bson.M{"keys": user.Keys}},
		},
		&opt,
	)

	if result.Err() != nil {
		return result.Err()
	}

	return nil
}

func DBGetUserKeys(uuid string, userid string) (*[]UserKeyJson, error) {
	keys := []UserKeyJson{}
	tenant := DBFindTenant(uuid)
	if tenant == nil {
		return &keys, fmt.Errorf("Unknown tenant")
	}
	user := DBFindUser(uuid, userid)
	if user == nil {
		return &keys, fmt.Errorf("User not found")
	}

	for _, k := range user.Keys {
		keys = append(keys, UserKeyJson{Name: k.Name})
	}
	return &keys, nil
}

type DomainOwner struct {
	Domain string `json:"domain" bson:"domain"`
	Tenant string `json:"tenant" bson:"tenant"`
}

func DBAddEmailOwner(email string, tenant string) error {
	owned := DomainOwner{Domain: email, Tenant: tenant}
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	err := domainsCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"domain": email},
		bson.D{
			{"$set", owned},
		},
		&opt,
	)
	if err.Err() != nil {
		return err.Err()
	}
	return nil
}

func DBDelEmailOwner(email string) error {
	_, err := domainsCltn.DeleteOne(
		context.TODO(),
		bson.M{"domain": email},
	)
	if err != nil {
		return err
	}
	return nil
}

func DBDelTenantOwnedDomains(uuid string) error {
	tenant := DBFindTenant(uuid)
	if tenant == nil {
		return fmt.Errorf("Unknown tenant")
	}
	for _, owned := range tenant.OwnedEmails {
		err := DBDelEmailOwner(owned)
		if err != nil {
			return err
		}
	}
	return nil
}

func DBGetEmailOwner(email string) (string, error) {
	var owner DomainOwner
	err := domainsCltn.FindOne(
		context.TODO(),
		bson.M{"domain": email},
	).Decode(&owner)
	if err != nil {
		// No tenant owns this email-domain yet
		if err == mongo.ErrNoDocuments {
			return "", nil
		}
		return "", err
	}
	return email, nil
}

func DBUpdateOwnedDomains(ownedDomain string, tenantid string) error {
	tenant := DBFindTenant(tenantid)
	if tenant == nil {
		return fmt.Errorf("Unknown tenant")
	}
	for _, o := range tenant.OwnedEmails {
		if o == ownedDomain {
			return nil
		}
	}
	curOwner, err := DBGetEmailOwner(ownedDomain)
	if err != nil {
		return err
	}
	if curOwner != "" && curOwner != tenant.ID {
		return fmt.Errorf("Domain name already registered by another customer, please contact sales@nextensio.com")
	}
	err = DBAddEmailOwner(ownedDomain, tenant.ID)
	if err != nil {
		return err
	}
	tenant.OwnedEmails = append(tenant.OwnedEmails, ownedDomain)
	err = dbUpdateTenant(tenant)
	if err != nil {
		DBDelEmailOwner(ownedDomain)
		return err
	}
	return nil
}

// This API will add/update a new user
func DBAddUser(uuid string, admin string, data *User) error {

	tenant := DBFindTenant(uuid)
	if tenant == nil {
		return fmt.Errorf("Unknown tenant")
	}

	user := DBFindUser(uuid, data.Uid)
	bundle := DBFindBundle(uuid, data.Uid)
	if bundle != nil {
		return fmt.Errorf("ID Already taken for an AppGroup, please use a different ID")
	}
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
	keys := []UserKey{}
	if user != nil {
		keys = user.Keys
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
	data.Services = []string{}

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
				"services": data.Services, "usertype": data.Usertype, "keys": keys,
				"ownedemails": tenant.OwnedEmails}},
		},
		&opt,
	)

	if result.Err() != nil {
		return result.Err()
	}
	dbUpdateUserInfoHdr(uuid, admin)

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
		uid := users[i]["_id"].(string)
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

func DBDelUser(tenant string, admin string, userid string) error {
	var user User

	uattr := DBFindUserAttr(tenant, userid)
	if uattr != nil {
		return fmt.Errorf("Delete user attributes before deleting user info")
	}
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
	dbUpdateUserInfoHdr(tenant, admin)

	return nil
}

func UserKeepalive(tenant string, user *User, keep Keepalive) error {
	upsert := false
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	userCltn := dbGetCollection(tenant, "NxtUsers")
	if userCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	found := false
	newKeep := []Keepalive{}
	for _, u := range user.Keepalive {
		if u.Device == keep.Device {
			if !found {
				newKeep = append(newKeep, keep)
				found = true
			}
		} else {
			// purge old entries
			t := time.Unix(u.Seen, 0)
			if time.Since(t) <= 3*time.Minute {
				newKeep = append(newKeep, u)
			}
		}
	}
	if !found {
		newKeep = append(newKeep, keep)
	}
	result := userCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": user.Uid},
		bson.D{
			{"$set", bson.M{"keepalive": newKeep}},
		},
		&opt,
	)
	if result.Err() != nil {
		return result.Err()
	}

	return nil
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

type UserStatus struct {
	Device  string `json:"device" bson:"device"`
	Gateway string `json:"gateway" bson:"gateway"`
	Source  string `json:"source" bson:"source"`
	Health  string `json:"health" bson:"health"`
}

func DBFindUserStatus(tenant string, userid string) []UserStatus {
	var status []UserStatus = []UserStatus{}

	user := DBFindUser(tenant, userid)
	if user == nil {
		return status
	}

	for _, k := range user.Keepalive {
		ip := int2ip(uint32(k.Gateway))
		t := time.Unix(k.Seen, 0)
		health := "offline"
		if time.Since(t) <= 3*time.Minute {
			health = "online"
		}
		us := UserStatus{Device: k.Device, Gateway: ip.String(), Source: k.Source, Health: health}
		status = append(status, us)
	}
	return status
}

// Common function to get default set of attributes for Users,
// or bundles
func dbGetDefaultAttrs(tenant string, appliesTo string) *bson.M {
	defAttr := make(bson.M, 0)
	attrset := DBFindSpecificAttrSet(tenant, appliesTo, "all")
	if attrset == nil || len(attrset) == 0 {
		return nil
	}
	nattrs := 0
	for _, a := range attrset {
		if strings.HasPrefix(a.Name, "_") {
			// Skip any system attributes
			continue
		}
		switch a.Type {
		case "String":
			if a.IsArray == "true" {
				defAttr[a.Name] = []string{}
			} else {
				defAttr[a.Name] = ""
			}
		case "Number":
			if a.IsArray == "true" {
				defAttr[a.Name] = []int{}
			} else {
				defAttr[a.Name] = 0
			}
		case "Boolean":
			defAttr[a.Name] = false
		case "Date":
			defAttr[a.Name] = ""
		}
		nattrs++
	}
	if nattrs == 0 {
		return nil
	}
	return &defAttr
}

// When adding a new bundle, we also create a bundle attributes doc with
// just the bid (key field). This is ok if no bundle attributes have
// been defined. But if bundle attributes have been defined, then create
// the bundle attributes doc with default values for those attributes
// defined.
// This function looks at the AttrSet to see if there are bundle attributes
// we should add to the doc.
func dbGetDefaultBundleAttr(tenant string) *bson.M {
	return dbGetDefaultAttrs(tenant, "Bundles")
}

// When adding a new user, we also create a user attributes doc with
// just the userid (key field). This is ok if no user attributes have
// been defined. But if user attributes have been defined, then create
// the user attributes doc with default values for those attributes
// defined.
// This function looks at the AttrSet to see if there are user attributes
// we should add to the doc.
func dbGetDefaultUserAttr(tenant string) *bson.M {
	return dbGetDefaultAttrs(tenant, "Users")
}

func dbCheckAttrGroupOwnership(tenant string, group string, appliesTo string, Xattr *bson.M, upd bool) (bool, string) {

	grp := group
	if group == "admin" || group == "superadmin" {
		grp = "all"
	}
	if !upd {
		// When adding attributes, all attributes need to be added in one
		// shot, not group by group. Updates of attribute values need to
		// be done by group.
		grp = "all"
	}
	attrset := DBFindSpecificAttrSet(tenant, appliesTo, grp)
	nattrs := 0
	if !upd {
		// New attributes are being added. A group admin has to add all
		// user attributes for that group only. An "admin" or "superadmin"
		// has to add all user attributes.
		for _, a := range attrset {
			if strings.HasPrefix(a.Name, "_") {
				// Skip any system attributes since their values
				// cannot be updated.
				continue
			}
			nattrs += 1
			found := false
			for k := range *Xattr {
				if k == a.Name {
					found = true
					break
				}
			}
			if !found {
				return false, "All attributes defined in AttributeEditor need to be present"
			}
		}
	}
	// Now check if all attributes passed in are part of attrset.
	// A group admin can update user attributes only for the group.
	// An "admin" or "superadmin" can update all user attributes.
	// For now, filter out attributes not belonging to group since
	// ux code sends all attributes if group admin is updating.
	invalid := false
	for k := range *Xattr {
		if strings.HasPrefix(k, "_") {
			// Cannot add/update a system user attribute
			invalid = true
			break
		}
		found := false
		for _, a := range attrset {
			if a.Name == k {
				found = true
				break
			}
		}
		if !found {
			delete(*Xattr, k)
			continue
			// invalid = true
			// break
		}
	}
	if invalid {
		return false, "Attribute list has attributes without required privilege"
	}
	return true, ""
}

func dbCheckUserAttrGroupOwnership(tenant string, group string, Uattr *bson.M, upd bool) (bool, string) {
	return dbCheckAttrGroupOwnership(tenant, group, "Users", Uattr, upd)
}

func dbCheckBundleAttrGroupOwnership(tenant string, group string, Uattr *bson.M, upd bool) (bool, string) {
	return dbCheckAttrGroupOwnership(tenant, group, "Bundles", Uattr, upd)
}

func dbAddUserAttr(uuid string, user string, Uattr bson.M, replace bool) error {
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
		if Uattr == nil || len(Uattr) == 0 {
			// This is an api call and no user attributes doc exists
			_, err := userAttrCltn.InsertOne(
				context.TODO(),
				bson.M{"_id": user},
			)
			if err != nil {
				glog.Errorf("User attribute doc insert error - %v", err)
				return err
			}
		} else {
			// This is an api call and a user attributes doc exists
			result := userAttrCltn.FindOneAndUpdate(
				context.TODO(),
				bson.M{"_id": user},
				bson.D{
					{"$set", Uattr},
				},
				&opt,
			)
			if result.Err() != nil {
				glog.Errorf("User attribute doc add/update error - %v", result.Err())
				return result.Err()
			}
		}
	} else {
		// A new attribute is being added or an attribute is being
		// deleted
		result, err := userAttrCltn.ReplaceOne(
			context.TODO(),
			bson.M{"_id": user},
			Uattr,
		)
		if err != nil {
			glog.Errorf("User attribute doc replace error - %v", err)
			return err
		}
		if result.MatchedCount == 0 {
			return fmt.Errorf("Did not update any user")
		}
	}
	return nil
}

// Bulk add/update of attributes for multiple users
func DBUpdateAttrsForMultipleUsers(uuid string, admin string, group string, Uattr []bson.M) error {
	if Uattr == nil || len(Uattr) == 0 {
		return nil
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
	// First check and ensure that admin has privileges for all attributes
	// involved. If everything is fine, then push the changes to the DB.
	for _, urec := range Uattr {
		_, ok := urec["uid"].(string)
		if !ok {
			continue
		}
		delete(urec, "uid")
		sts, errstr := dbCheckUserAttrGroupOwnership(uuid, group, &urec, true)
		if !sts {
			return fmt.Errorf(errstr)
		}
	}
	count := 0
	for _, urec := range Uattr {
		user, ok := urec["uid"].(string)
		if !ok {
			continue
		}
		delete(urec, "uid")
		result := userAttrCltn.FindOneAndUpdate(
			context.TODO(),
			bson.M{"_id": user},
			bson.D{
				{"$set", urec},
			},
			&opt,
		)
		if result.Err() != nil {
			return result.Err()
		}
		count++
	}
	if count > 0 {
		// Some user attribute docs were updated
		dbUpdateUserAttrHdr(uuid, admin)
		glog.Infof("DBUpdateAttrsForMultpleUsers: updated %d users", count)
	} else {
		glog.Infof("DBUpdateAttrsForMultpleUsers: could not update any users")
	}
	return nil
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
func DBAddUserAttr(uuid string, admin string, user string, group string, Uattr bson.M) error {
	// Ensure the user info doc exists first before adding an attribute doc
	// for that user.
	dbUser := DBFindUser(uuid, user)
	if dbUser == nil {
		glog.Errorf("AddUserAttr: cannot find user " + user)
		return fmt.Errorf("Cannot find user " + user)
	}

	uattrLock.Lock()
	defer uattrLock.Unlock()
	upd := false
	uattr := DBFindUserAttr(uuid, user)
	if Uattr != nil {
		// User attribute add or update via api. Figure out if it's
		// an add or an update.
		if uattr != nil {
			// A user attributes doc exists. If the doc has just the key
			// field, it's an add case, else an update.
			if len(*uattr) > 1 {
				upd = true
			}
		}
		sts, errstr := dbCheckUserAttrGroupOwnership(uuid, group, &Uattr, upd)
		if !sts {
			return fmt.Errorf(errstr)
		}
	}

	if Uattr == nil || len(Uattr) == 0 {
		if uattr != nil {
			// user attributes doc exists and no new user attributes supplied,
			// so just return
			return nil
		} else {
			// user attributes doc does not exist and no user attributes have
			// been supplied. See if AttrSet has any attributes defined, and
			// if so, add them with default values.
			defAttr := dbGetDefaultUserAttr(uuid)
			if defAttr != nil {
				Uattr = *defAttr
			}
		}
	}
	err := dbAddUserAttr(uuid, user, Uattr, false)
	if err == nil {
		dbUpdateUserAttrHdr(uuid, admin)
	}
	return err
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
		uid := userAttrs[i]["_id"].(string)
		if uid != hdockey {
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

func DBDelUserAttr(tenant string, admin string, userid string) error {
	userAttrCltn := dbGetCollection(tenant, "NxtUserAttr")
	if userAttrCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	uattrLock.Lock()
	defer uattrLock.Unlock()
	_, err := userAttrCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": userid},
	)

	if err == nil {
		dbUpdateUserAttrHdr(tenant, admin)
	}
	return err
}

func DBDelAllUsersOneAttr(tenant string, admin string, todel string) error {

	if strings.HasPrefix(todel, "_") {
		// Silently ignore system attributes (names starting with _)
		return nil
	}

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
		var attr bson.M = make(bson.M)
		if err = cursor.Decode(&attr); err != nil {
			break
		}
		if attr["_id"].(string) == HDRKEY {
			continue
		}
		delete(attr, todel)
		if err = dbAddUserAttr(tenant, attr["_id"].(string), attr, true); err != nil {
			break
		}
	}
	// If there is an error midway, don't update header version.
	// We don't want minion to pick up a mangled collection.
	// Hopefully, such errors will not happen, else we need to
	// figure out how to recover from such errors.
	if err == nil {
		dbUpdateUserAttrHdr(tenant, admin)
	}
	return err
}

func DBAddAllUsersOneAttr(tenant string, admin string, set AttrSet) error {

	if strings.HasPrefix(set.Name, "_") {
		// Silently ignore system attributes (names starting with _)
		return nil
	}

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
		var attr bson.M = make(bson.M)
		if err = cursor.Decode(&attr); err != nil {
			break
		}
		key := attr["_id"].(string)
		if key == HDRKEY {
			continue
		}
		attr[set.Name] = value
		glog.Infof("Adding attribute " + set.Name + " to user " + key)
		if err = dbAddUserAttr(tenant, key, attr, true); err != nil {
			break
		}
	}
	// If there is an error midway, don't update header version.
	// We don't want minion to pick up a mangled collection.
	// Hopefully, such errors will not happen, else we need to
	// figure out how to recover from such errors.
	if err == nil {
		dbUpdateUserAttrHdr(tenant, admin)
	}
	return err
}

//----------------------App bundle Info and Attributes-----------------------

// This API will add/update a bundle info Header
func dbAddBundleInfoHdr(uuid string, admin string, data *DataHdr) error {

	return dbAddCollectionHdr(uuid, admin, data, "NxtApps", "AppInfo")
}

// This API will update a bundle Info Header
func dbUpdateBundleInfoHdr(uuid string, admin string) error {

	return dbUpdateCollectionHdr(uuid, admin, "NxtApps", "AppInfo")
}

func DBFindBundleInfoHdr(tenant string) *DataHdr {

	return dbFindCollectionHdr(tenant, "NxtApps", "AppInfo")
}

func dbDelBundleInfoHdr(tenant string) error {

	return dbDelCollectionHdr(tenant, "NxtApps", "AppInfo")
}

// This API will add a bundle Attribute Header
func dbAddBundleAttrHdr(uuid string, admin string, data *DataHdr) error {

	return dbAddCollectionHdr(uuid, admin, data, "NxtAppAttr", "AppAttr")
}

// This API will update a bundle Attribute Header
func dbUpdateBundleAttrHdr(uuid string, admin string) error {

	return dbUpdateCollectionHdr(uuid, admin, "NxtAppAttr", "AppAttr")
}

func DBFindBundleAttrHdr(tenant string) *DataHdr {

	return dbFindCollectionHdr(tenant, "NxtAppAttr", "AppAttr")
}

func dbDelBundleAttrHdr(tenant string) error {

	return dbDelCollectionHdr(tenant, "NxtAppAttr", "AppAttr")
}

// The Pod here indicates the "pod set" that this user should
// connect to, each pod set has its own number of replicas etc..
type Bundle struct {
	Bid           string      `json:"bid" bson:"_id"`
	Bundlename    string      `json:"name" bson:"name"`
	Gateway       string      `json:"gateway" bson:"gateway"`
	Pod           string      `json:"pod" bson:"pod"`
	Connectid     string      `json:"connectid" bson:"connectid"`
	Services      []string    `json:"services" bson:"services"`
	CpodRepl      int         `json:"cpodrepl" bson:"cpodrepl"`
	SharedKey     string      `json:"sharedkey" bson:"sharedkey"`
	Keepalive     []Keepalive `json:"keepalive" bson:"keepalive"`
	ConfigVersion uint64      `json:"cfgvn" bson:"cfgvn"`
}

// This API will add/update a new bundle
func DBAddBundle(uuid string, admin string, data *Bundle) error {

	tenant := DBFindTenant(uuid)
	if tenant == nil {
		return fmt.Errorf("Unknown tenant")
	}
	user := DBFindUser(uuid, data.Bid)
	if user != nil {
		return fmt.Errorf("ID already taken for a user, please use different id")
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

	if bundle != nil {
		data.SharedKey = bundle.SharedKey
		// Find out if any services have changed
		found := false
		for _, osvc := range bundle.Services {
			for _, nsvc := range data.Services {
				if osvc == nsvc {
					found = true
					break
				}
			}
			if !found {
				data.ConfigVersion = uint64(time.Now().Unix())
				break
			}
		}
		if !found {
			for _, nsvc := range data.Services {
				for _, osvc := range bundle.Services {
					if nsvc == osvc {
						found = true
						break
					}
				}
				if !found {
					data.ConfigVersion = uint64(time.Now().Unix())
					break
				}
			}
		}
	} else {
		s, e := GenMyJwt("bundlekey", uuid, data.Bid, "regular")
		if e != nil {
			return e
		}
		data.SharedKey = s
	}

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
				"services": data.Services, "cpodrepl": data.CpodRepl,
				"sharedkey": data.SharedKey, "cfgvn": data.ConfigVersion}},
		},
		&opt,
	)
	if result.Err() != nil {
		return result.Err()
	}
	dbUpdateBundleInfoHdr(uuid, admin)

	err := DBAddClusterBundle(uuid, data)
	if err != nil {
		return err
	}

	return nil
}

func DBUpdateBundle(tenant string, admin string, data *Bundle) error {

	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	appCltn := dbGetCollection(tenant, "NxtApps")
	if appCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	result := appCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": data.Bid},
		bson.D{
			{"$set", bson.M{"name": data.Bundlename,
				"gateway": data.Gateway, "pod": data.Pod, "connectid": data.Connectid,
				"services": data.Services, "cpodrepl": data.CpodRepl,
				"sharedkey": data.SharedKey, "cfgvn": data.ConfigVersion}},
		},
		&opt,
	)
	if result.Err() != nil {
		return result.Err()
	}
	dbUpdateBundleInfoHdr(tenant, admin)

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
		bid := bundles[i]["_id"].(string)
		if bid != hdockey {
			if bundles[i]["services"] != nil {
				svcs := bundles[i]["services"].(primitive.A)
				bundles[i]["services"] = svcs
			}
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

func DBDelBundle(tenant string, admin string, bundleid string) error {
	var bun Bundle

	battr := DBFindBundleAttr(tenant, bundleid)
	if battr != nil {
		return fmt.Errorf("Delete AppGroup attributes before deleting AppGroup info")
	}
	appCltn := dbGetCollection(tenant, "NxtApps")
	if appCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	err := appCltn.FindOne(context.TODO(), bson.M{"_id": bundleid}).Decode(&bun)
	if err != nil {
		return fmt.Errorf("Request to delete unknown AppGroup %s", bundleid)
	}
	_, err = appCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": bundleid},
	)
	if err != nil {
		return err
	}
	dbUpdateBundleInfoHdr(tenant, admin)

	err = DBDelClusterBundle(tenant, bundleid)
	if err != nil {
		return err
	}

	return err
}

func BundleKeepalive(tenant string, bundle *Bundle, keep Keepalive) error {
	upsert := false
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	appCltn := dbGetCollection(tenant, "NxtApps")
	if appCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	found := false
	newKeep := []Keepalive{}
	for _, b := range bundle.Keepalive {
		if b.Device == keep.Device {
			if !found {
				newKeep = append(newKeep, keep)
				found = true
			}
		} else {
			// purge old entries
			t := time.Unix(b.Seen, 0)
			if time.Since(t) <= 3*time.Minute {
				newKeep = append(newKeep, b)
			}
		}
	}
	if !found {
		newKeep = append(newKeep, keep)
	}
	result := appCltn.FindOneAndUpdate(
		context.TODO(),
		bson.M{"_id": bundle.Bid},
		bson.D{
			{"$set", bson.M{"keepalive": newKeep}},
		},
		&opt,
	)
	if result.Err() != nil {
		return result.Err()
	}

	return nil
}

type BundleStatus struct {
	Device  string `json:"device" bson:"device"`
	Gateway string `json:"gateway" bson:"gateway"`
	Source  string `json:"source" bson:"source"`
	Health  string `json:"health" bson:"health"`
}

func DBFindBundleStatus(tenant string, bid string) []BundleStatus {
	var status []BundleStatus = []BundleStatus{}

	bundle := DBFindBundle(tenant, bid)
	if bundle == nil {
		return status
	}

	for _, k := range bundle.Keepalive {
		ip := int2ip(uint32(k.Gateway))
		t := time.Unix(k.Seen, 0)
		health := "offline"
		if time.Since(t) <= 3*time.Minute {
			health = "online"
		}
		bs := BundleStatus{Device: k.Device, Gateway: ip.String(), Source: k.Source, Health: health}
		status = append(status, bs)
	}
	return status
}

func dbAddBundleAttr(uuid string, bid string, Battr bson.M, replace bool) error {

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
		if Battr == nil || len(Battr) == 0 {
			_, err := appAttrCltn.InsertOne(
				context.TODO(),
				bson.M{"_id": bid},
			)
			if err != nil {
				glog.Errorf("AppGroup attribute doc insert error - %v", err)
				return err
			}
		} else {
			result := appAttrCltn.FindOneAndUpdate(
				context.TODO(),
				bson.M{"_id": bid},
				bson.D{{"$set", Battr}},
				&opt,
			)
			if result.Err() != nil {
				glog.Errorf("AppGroup attribute doc add/update error - %v", result.Err())
				return result.Err()
			}
		}
	} else {
		result, err := appAttrCltn.ReplaceOne(
			context.TODO(),
			bson.M{"_id": bid},
			Battr,
		)
		if err != nil {
			glog.Errorf("AppGroup attribute doc replace error - %v", err)
			return err
		}
		if result.MatchedCount == 0 {
			return fmt.Errorf("Did not update any AppGroup")
		}
	}
	return nil
}

func dbUpdateBundleServices(tenant string, admin string, app string) {
	// Get all bundles
	// For each bundle, check if it has any service(s) matching the incoming
	// service name. If so, remove the service(s) and update the bundle
	bundles := DBFindAllBundlesStruct(tenant)
	if bundles == nil {
		return
	}
	for _, b := range bundles {
		nsvcs := []string{}
		changed := false
		for _, svc := range b.Services {
			if strings.Contains(svc, app) {
				changed = true
				continue
			}
			nsvcs = append(nsvcs, svc)
		}
		if changed {
			b.Services = nsvcs
			b.ConfigVersion = uint64(time.Now().Unix())
			DBUpdateBundle(tenant, admin, &b)
			glog.Infof("dbUpdateBundleServices: updated bundle %s services to %v", b.Bid, nsvcs)
		}
	}
}

func DBUpdateBundleServices(uuid string, admin string, host string, deleted *[]string) {
	for _, tag := range *deleted {
		dbUpdateBundleServices(uuid, admin, tag+"."+host)
		glog.Infof("DBUpdateBundleService: deleted tagged app %s from AppGroup services", tag+"."+host)
	}
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
func DBAddBundleAttr(uuid string, admin string, bid string, group string, Battr bson.M) error {
	dbBundle := DBFindBundle(uuid, bid)
	if dbBundle == nil {
		glog.Errorf("AddAppGroupAttr: cannot find AppGroup " + bid)
		return fmt.Errorf("Cannot find bundle")
	}

	battrLock.Lock()
	defer battrLock.Unlock()
	upd := false
	battr := DBFindBundleAttr(uuid, bid)
	if Battr != nil {
		// Bundle attributes add or update via api. Figure out if it's an
		// add or update
		if battr != nil {
			// A bundle attributes doc exists. If the doc has just the
			// key field, it's an add case, else an update
			if len(*battr) > 1 {
				upd = true
			}
		}
		sts, errstr := dbCheckBundleAttrGroupOwnership(uuid, group, &Battr, upd)
		if !sts {
			return fmt.Errorf(errstr)
		}
	}

	if Battr == nil || len(Battr) == 0 {
		if battr != nil {
			// Bundle attributes doc exists and no new bundle attributes
			// supplied, so just return
			return nil
		} else {
			// bundle attributes doc does not exist and no bundle attributes have
			// been supplied. See if AttrSet has any attributes defined, and
			// if so, add them with default values.
			defAttr := dbGetDefaultBundleAttr(uuid)
			if defAttr != nil {
				Battr = *defAttr
			}
		}
	}
	err := dbAddBundleAttr(uuid, bid, Battr, false)
	if err == nil {
		dbUpdateBundleAttrHdr(uuid, admin)
	}
	return err
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
		bid := bundleAttrs[i]["_id"].(string)
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

func DBDelBundleAttr(tenant string, admin string, bundleid string) error {
	appAttrCltn := dbGetCollection(tenant, "NxtAppAttr")
	if appAttrCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	battrLock.Lock()
	defer battrLock.Unlock()
	_, err := appAttrCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": bundleid},
	)

	if err == nil {
		dbUpdateBundleAttrHdr(tenant, admin)
	}
	return err
}

func DBDelAllBundlesOneAttr(tenant string, admin string, todel string) error {

	if strings.HasPrefix(todel, "_") {
		// Silently ignore system attributes (names starting with _)
		return nil
	}

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
		var attr bson.M = make(bson.M)
		if err = cursor.Decode(&attr); err != nil {
			break
		}
		if attr["_id"].(string) == HDRKEY {
			continue
		}
		delete(attr, todel)
		if err = dbAddBundleAttr(tenant, attr["_id"].(string), attr, true); err != nil {
			break
		}
	}
	// If there is an error midway, don't update header version.
	// We don't want minion to pick up a mangled collection.
	// Hopefully, such errors will not happen, else we need to
	// figure out how to recover from such errors.
	if err == nil {
		dbUpdateBundleAttrHdr(tenant, admin)
	}
	return err
}

func DBAddAllBundlesOneAttr(tenant string, admin string, set AttrSet) error {

	if strings.HasPrefix(set.Name, "_") {
		// Silently ignore system attributes (names starting with _)
		return nil
	}

	appAttrCltn := dbGetCollection(tenant, "NxtAppAttr")
	if appAttrCltn == nil {
		return fmt.Errorf("Cant find AppGroup collection")
	}
	cursor, err := appAttrCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return err
	}

	value := defaultType(set)

	defer cursor.Close(context.TODO())
	for cursor.Next(context.TODO()) {
		var attr bson.M = make(bson.M)
		if err = cursor.Decode(&attr); err != nil {
			break
		}
		if attr["_id"].(string) == HDRKEY {
			continue
		}
		attr[set.Name] = value
		if err = dbAddBundleAttr(tenant, attr["_id"].(string), attr, true); err != nil {
			break
		}
	}
	// If there is an error midway, don't update header version.
	// We don't want minion to pick up a mangled collection.
	// Hopefully, such errors will not happen, else we need to
	// figure out how to recover from such errors.
	if err == nil {
		dbUpdateBundleAttrHdr(tenant, admin)
	}
	return err
}

//-------------------------------Host Attributes -------------------------

// This API will add a Host Attributes Header
func dbAddHostAttrHdr(uuid string, admin string, data *DataHdr) error {

	return dbAddCollectionHdr(uuid, admin, data, "NxtHostAttr", "HostAttr")

}

// This API will update a Host Attributes Header
func dbUpdateHostAttrHdr(uuid string, admin string) error {

	return dbUpdateCollectionHdr(uuid, admin, "NxtHostAttr", "HostAttr")

}

func DBFindHostAttrHdr(tenant string) *DataHdr {

	return dbFindCollectionHdr(tenant, "NxtHostAttr", "HostAttr")
}

func dbDelHostAttrHdr(tenant string) error {

	return dbDelCollectionHdr(tenant, "NxtHostAttr", "HostAttr")
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
		host := hostAttrs[i]["_id"].(string)
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
		host := hostAttrs[i]["_id"].(string)
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
	return nil
}

func DBValidateHostId(host string) string {
	// Host ID format is label1[.label2][.label3]...[:port]
	// No label should have length > 63
	labels := strings.Split(host, ".")
	numlabels := len(labels)
	for i, lbl := range labels {
		if len(lbl) > 63 {
			return "Invalid Host ID (" + host + ") - contains label with length > 63"
		}
		if (i < (numlabels - 1)) && strings.Contains(lbl, ":") {
			return "Invalid Host ID (" + host + ") - label contains : character"
		}
	}
	return ""
}

// This API will add/update a host attributes doc
// A host can be added without any routes. When the host is added,
// all agents need to be notified because the domain list changes.
// After that, routes can be added incrementally or a route deleted.
// Each route that is added has a tag and associated attributes. The
// attributes must always exactly match the list of Host attributes
// defined in the AttrSet (via say attribute editor).
// Existing route tag attribute values can be changed for one or more
// route tags. These are the possibilities:
// 1. all existing route tags are being updated
// 2. only a subset of route tags are being updated, leaving the others intact
// 3. only a subset of route tags are being updated while deleting the rest
// 4. one or more route tags are being added to existing route tags
// 5. only a subset of route tags are being updated while adding one or more.
func DBAddHostAttr(uuid string, admin string, data []byte) error {
	var Hattr bson.M

	err := json.Unmarshal(data, &Hattr)
	if err != nil {
		return err
	}
	host := Hattr["host"].(string)
	delete(Hattr, "host")

	attrs := Hattr["routeattrs"].([]interface{})
	// First check if there are duplicate route tags
	tags := make(map[string]bool, 0)
	for _, a := range attrs {
		route := a.(map[string]interface{})
		tag := route["tag"].(string)
		_, ok := tags[tag]
		if ok {
			glog.Errorf("AddHostAttr: duplicate route tag found - " + tag)
			return fmt.Errorf("Duplicate route tag name")
		}
		tags[tag] = true
	}

	hattrLock.Lock()
	defer hattrLock.Unlock()
	// See if we have a new host or it's an existing host
	hosts := DBFindAllHosts(uuid)
	hostfound := false
	for _, h := range hosts {
		if h == host {
			hostfound = true
			break
		}
	}
	// Ensure that hostid is in a valid format if new host being
	// added
	if !hostfound {
		sts := DBValidateHostId(host)
		if sts != "" {
			glog.Errorf("AddHostAttr: Invalid host id format for " + host)
			return fmt.Errorf(sts)
		}
	}

	// Now ensure that every attribute defined for hosts in AttrSet
	// is included in the attributes being added.
	attrset := DBFindSpecificAttrSet(uuid, "Hosts", "all")
	nattrs := 0
	for _, a := range attrset {
		nattrs += 1
		for _, r := range attrs {
			found := false
			route := r.(map[string]interface{})
			for k := range route {
				if k == a.Name {
					found = true
					break
				}
			}
			if !found {
				// Add the attribute from the AttrSet if missing. Don't
				// flag an error.
				switch a.Type {
				case "String":
					if a.IsArray == "true" {
						route[a.Name] = []string{}
					} else {
						route[a.Name] = ""
					}
				case "Number":
					if a.IsArray == "true" {
						route[a.Name] = []int{}
					} else {
						route[a.Name] = 0
					}
				case "Boolean":
					route[a.Name] = false
				case "Date":
					route[a.Name] = ""
				}
			}
		}
	}
	// Now ensure that every attribute being added is in AttrSet
	for _, r := range attrs {
		route := r.(map[string]interface{})
		for k := range route {
			// Skip the route tag entry
			if k == "tag" {
				continue
			}
			found := false
			for _, a := range attrset {
				if k == a.Name {
					found = true
					break
				}
			}
			if !found {
				glog.Errorf("AddHostAttr: attribute not in AttrSet - " + k)
				return fmt.Errorf("Attribute being added is not defined in AttributeEditor - " + k)
			}
		}
	}

	missing := []primitive.M{}
	missing_tag := []string{}
	hostattrfound := false

	// TODO: why WHY! do we deal with this whole this as raw json, why cant
	// we make it a nice golang struct ? open a ticket and get that done

	// If we had found the host, see what route tags and attributes already
	// exist for that host.
	if hostfound {
		existing := DBFindHostAttr(uuid, host)
		if existing != nil {
			// Some route tags and attributes exist for this host.
			// See if any route tags and their attributes are missing in
			// the new data supplied.
			hostattrfound = true
			oldattrs := (*existing)["routeattrs"].(primitive.A)
			for _, o := range oldattrs {
				found := false
				old := o.(primitive.M)
				ot := old["tag"].(string)
				for _, r := range attrs {
					new := r.(map[string]interface{})
					nt := new["tag"].(string)
					if ot == nt {
						found = true
						break
					}
				}
				if !found {
					missing = append(missing, old)
					missing_tag = append(missing_tag, ot)
				}
			}
			update := false
			if val, ok := Hattr["update"]; ok {
				update = val.(bool)
			}
			// If "update" is true, then the intent is a union/updation on top of
			// existing tags rather than deleting anything.
			if update {
				for _, m := range missing {
					attrs = append(attrs, m)
				}
				Hattr["routeattrs"] = attrs
				missing_tag = []string{}
			} else {
				// Just take the new data passed in and overwrite existing data.
				// Check if any deleted route is still being referred to in the route policy
				if len(missing_tag) > 0 && DBHostRuleExists(uuid, host, &missing_tag) {
					return fmt.Errorf("Please update rules/policy for the deleted route(s) of %s first - %v", host, missing_tag)
				}
			}
		}
	}

	err = dbAddHostAttr(uuid, host, Hattr, false)
	if err != nil {
		return err
	}
	dbUpdateHostAttrHdr(uuid, admin)

	if !hostfound {
		// Adding a new host, aka App. Add it to tenant's domain list.
		err = dbaddTenantDomain(uuid, host)
		if err != nil {
			return err
		}
	} else {
		if hostattrfound && len(missing_tag) > 0 {
			// Remove tagged app entries for any deleted routes from AppGroups
			DBUpdateBundleServices(uuid, admin, host, &missing_tag)
		}
	}

	return nil
}

func DBDelHostAttr(tenant string, admin string, hostid string) error {
	if DBHostRuleExists(tenant, hostid, nil) {
		return fmt.Errorf("Please update Route policy for the route before deleting the route")
	}
	hostAttrCltn := dbGetCollection(tenant, "NxtHostAttr")
	if hostAttrCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}

	hattrLock.Lock()
	defer hattrLock.Unlock()
	_, err := hostAttrCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": hostid},
	)
	if err != nil {
		return err
	}
	dbUpdateHostAttrHdr(tenant, admin)
	dbUpdateBundleServices(tenant, admin, hostid)
	err = dbdelTenantDomain(tenant, hostid)
	if err != nil {
		return err
	}

	return nil
}

func DBDelAllHostsOneAttr(tenant string, admin string, todel string) error {

	if strings.HasPrefix(todel, "_") {
		// Silently ignore system attributes (names starting with _)
		return nil
	}

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
		var attr bson.M = make(bson.M)
		if err = cursor.Decode(&attr); err != nil {
			break
		}
		if attr["_id"].(string) != "Header" {
			attrs := attr["routeattrs"].(primitive.A)
			for _, r := range attrs {
				route := r.(primitive.M)
				delete(route, todel)
			}
			if err = dbAddHostAttr(tenant, attr["_id"].(string), attr, true); err != nil {
				break
			}
		}
	}
	// If there is an error midway, don't update header version.
	// We don't want minion to pick up a mangled collection.
	// Hopefully, such errors will not happen, else we need to
	// figure out how to recover from such errors.
	if err == nil {
		dbUpdateHostAttrHdr(tenant, admin)
	}
	return err
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

func DBAddAllHostsOneAttr(tenant string, admin string, set AttrSet) error {

	if strings.HasPrefix(set.Name, "_") {
		// Silently ignore system attributes (names starting with _)
		return nil
	}

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
		var attr bson.M = make(bson.M)
		if err = cursor.Decode(&attr); err != nil {
			break
		}
		if attr["_id"].(string) != "Header" {
			attrs := attr["routeattrs"].(primitive.A)
			for _, r := range attrs {
				route := r.(primitive.M)
				route[set.Name] = value
			}
			if err = dbAddHostAttr(tenant, attr["_id"].(string), attr, true); err != nil {
				break
			}
		}
	}
	// If there is an error midway, don't update header version.
	// We don't want minion to pick up a mangled collection.
	// Hopefully, such errors will not happen, else we need to
	// figure out how to recover from such errors.
	if err == nil {
		dbUpdateHostAttrHdr(tenant, admin)
	}
	return err
}

//-------------------------------Trace Attributes -------------------------

// This API will add a Trace Requests Header
func dbAddTraceRequestsHdr(uuid string, admin string, data *DataHdr) error {

	return dbAddCollectionHdr(uuid, admin, data, "NxtTraceRequests", "TraceReqs")

}

// This API will update a Trace Requests Header
func dbUpdateTraceRequestsHdr(uuid string, admin string) error {

	return dbUpdateCollectionHdr(uuid, admin, "NxtTraceRequests", "TraceReqs")

}

func DBFindTraceRequestsHdr(tenant string) *DataHdr {

	return dbFindCollectionHdr(tenant, "NxtTraceRequests", "TraceReqs")
}

func dbDelTraceRequestsHdr(tenant string) error {

	return dbDelCollectionHdr(tenant, "NxtTraceRequests", "TraceReqs")
}

func dbAddTraceReq(uuid string, traceid string, Uattr bson.M, replace bool) error {
	// The upsert option asks the DB to add if one is not found
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	traceReqCltn := dbGetCollection(uuid, "NxtTraceRequests")
	if traceReqCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	if !replace {
		result := traceReqCltn.FindOneAndUpdate(
			context.TODO(),
			bson.M{"_id": traceid},
			bson.D{
				{"$set", Uattr},
			},
			&opt,
		)
		if result.Err() != nil {
			return result.Err()
		}
	} else {
		result, err := traceReqCltn.ReplaceOne(
			context.TODO(),
			bson.M{"_id": traceid},
			Uattr,
		)
		if err != nil {
			return err
		}
		if result.MatchedCount == 0 {
			return fmt.Errorf("Did not update any trace request")
		}
	}
	return nil
}

// This API will add a new trace requests doc or update existing one
func DBAddTraceReq(uuid string, admin string, traceid string, Uattr bson.M) error {

	err := dbAddTraceReq(uuid, traceid, Uattr, false)
	if err == nil {
		dbUpdateTraceRequestsHdr(uuid, admin)
	}
	return err
}

// Find a specific trace request
func DBFindTraceReq(tenant string, traceid string) *bson.M {
	var tracereq bson.M
	traceReqCltn := dbGetCollection(tenant, "NxtTraceRequests")
	if traceReqCltn == nil {
		return nil
	}
	err := traceReqCltn.FindOne(
		context.TODO(),
		bson.M{"_id": traceid},
	).Decode(&tracereq)
	if err != nil {
		return nil
	}
	tracereq["traceid"] = tracereq["_id"]
	delete(tracereq, "_id")
	return &tracereq
}

// Get all trace requests
func DBFindAllTraceReqs(tenant string) []bson.M {
	var tracereqs []bson.M

	traceReqCltn := dbGetCollection(tenant, "NxtTraceRequests")
	if traceReqCltn == nil {
		return nil
	}
	cursor, err := traceReqCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil
	}
	err = cursor.All(context.TODO(), &tracereqs)
	if err != nil {
		return nil
	}

	if len(tracereqs) == 0 {
		return nil
	}
	hdockey := DBGetHdrKey("TraceReqs")
	ntracereqs := make([]bson.M, len(tracereqs))
	j := 0
	for i := 0; i < len(tracereqs); i++ {
		// Need to skip header doc
		trcid := tracereqs[i]["_id"].(string)
		if trcid != hdockey {
			ntracereqs[j] = tracereqs[i]
			ntracereqs[j]["traceid"] = tracereqs[i]["_id"]
			delete(ntracereqs[j], "_id")
			j++
		}
	}
	if len(ntracereqs[:j]) == 0 {
		return nil
	}
	return ntracereqs[:j]
}

// Delete a trace request
func DBDelTraceReq(tenant string, admin string, traceid string) error {
	traceReqCltn := dbGetCollection(tenant, "NxtTraceRequests")
	if traceReqCltn == nil {
		return fmt.Errorf("Unknown Collection")
	}
	_, err := traceReqCltn.DeleteOne(
		context.TODO(),
		bson.M{"_id": traceid},
	)

	if err == nil {
		dbUpdateTraceRequestsHdr(tenant, admin)
	}
	return err
}

// Remove one attribute from all trace requests
func DBDelAllTraceReqsOneAttr(tenant string, admin string, attrtodel string) error {
	var tracereq bson.M

	traceReqCltn := dbGetCollection(tenant, "NxtTraceRequests")
	if traceReqCltn == nil {
		return fmt.Errorf("Cant find trace request collection")
	}
	cursor, err := traceReqCltn.Find(context.TODO(), bson.M{})
	if err != nil {
		return err
	}
	defer cursor.Close(context.TODO())
	for cursor.Next(context.TODO()) {
		if err = cursor.Decode(&tracereq); err != nil {
			break
		}
		if tracereq["_id"].(string) == HDRKEY {
			continue
		}
		delete(tracereq, attrtodel)
		if err = dbAddTraceReq(tenant, tracereq["_id"].(string), tracereq, true); err != nil {
			break
		}
	}
	// If there is an error midway, don't update header version.
	// We don't want minion to pick up a mangled collection.
	// Hopefully, such errors will not happen, else we need to
	// figure out how to recover from such errors.
	if err == nil {
		dbUpdateTraceRequestsHdr(tenant, admin)
	}
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
