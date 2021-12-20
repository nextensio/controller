package okta

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/golang/glog"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func makeUserId(userid string) string {
	return userid
}

//----------------------------------------User API functions------------------------------------

// Get user info
func GetUserInfo(API string, TOKEN string, userid string) (string, string, string, error) {
	_, client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		return "", "", "", err
	}
	filter := query.NewQueryParams(query.WithFilter("profile.login eq \"" + makeUserId(userid) + "\""))
	users, _, err := client.User.ListUsers(context.TODO(), filter)
	if err != nil {
		return "", "", "", err
	}
	if len(users) != 1 {
		return "", "", "", err
	}
	return users[0].Id, (*users[0].Profile)["organization"].(string), (*users[0].Profile)["userType"].(string), nil
}

// Add user to Okta
func AddUser(API string, TOKEN string, userid string, tenant string, userType string, signup bool) (string, error) {
	_, client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		return "", err
	}
	oktaId, oktaTenant, oktaUsertype, e := GetUserInfo(API, TOKEN, userid)
	if e == nil && oktaId != "" {
		// User already exists
		glog.Infof("User " + userid + "/" + oktaId + " found")
		if signup {
			glog.Infof("Signup - User " + userid + "/" + oktaId + " already exists")
			return "", errors.New("User " + userid + " already exists")
		}
		if oktaTenant != tenant {
			glog.Errorf("User " + userid + "/" + oktaId + " exists but tenant mismatch " + tenant + "/" + oktaTenant)
			return "", errors.New("User already assigned to another tenant")
		}
		e = UpdateUser(client, userid, tenant, oktaUsertype)
		if e != nil {
			glog.Infof("User update failed for " + userid + "/" + oktaId)
			return "", e
		}
		glog.Infof("User with oktaId " + oktaId + " found")
		return oktaId, nil
	} else {
		glog.Infof("AddUser: user " + userid + " not found; creating...")
		profile := okta.UserProfile{}
		profile["firstName"] = "Nextensio"
		profile["lastName"] = "Customer"
		profile["email"] = userid
		profile["login"] = makeUserId(userid)
		profile["organization"] = tenant
		profile["userType"] = userType
		u := &okta.CreateUserRequest{
			Profile: &profile,
		}
		user, _, err := client.User.CreateUser(context.TODO(), *u, nil)
		if err != nil {
			glog.Errorf("AddUser: create for " + userid + " failed")
			return "", err
		}
		glog.Infof("AddUser: created user " + userid + " with id " + user.Id + " for tenant " + tenant)
		return user.Id, nil
	}
}

func DelUser(API string, TOKEN string, userid string, tenant string) error {
	_, client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		return err
	}
	oktaId, oktaTenant, _, e := GetUserInfo(API, TOKEN, userid)
	if e != nil {
		return e
	}
	if oktaTenant != tenant {
		glog.Errorf("user %s is part of tenant [%s], I am part of tenant[%s]", userid, oktaTenant, tenant)
		return errors.New("Cannot delete user belonging to another tenant")
	}
	oktaGid, err := CheckGroup(client, tenant, false)
	if oktaGid != "" {
		_, err = client.Group.RemoveUserFromGroup(context.TODO(), oktaGid, oktaId)
		glog.Infof("DelUser: user "+userid+" removed from group for tenant "+tenant+" - %v", err)
	}
	_, err = client.User.DeactivateUser(context.TODO(), oktaId, nil)
	if err != nil {
		glog.Errorf("DelUser: user "+userid+" deactivation for tenant "+tenant+" failed - %v", err)
		return err
	}
	_, err = client.User.DeactivateOrDeleteUser(context.TODO(), oktaId, nil)
	if err != nil {
		glog.Errorf("DelUser: user "+userid+" deletion for tenant "+tenant+" failed - %v", err)
		return err
	}
	glog.Infof("DelUser: user " + userid + " deleted for tenant " + tenant)

	return nil
}

func UpdateUser(client *okta.Client, oktaId string, tenant string, userType string) error {
	user, _, err := client.User.GetUser(context.TODO(), oktaId)
	if err != nil {
		return err
	}
	newProfile := *user.Profile
	newProfile["organization"] = tenant
	newProfile["userType"] = userType
	updatedUser := &okta.User{
		Profile: &newProfile,
	}
	_, _, err = client.User.UpdateUser(context.TODO(), oktaId, *updatedUser, nil)
	if err != nil {
		glog.Errorf("UpdateUser: user "+oktaId+" updation for tenant "+tenant+" failed - %v", err)
		return err
	}
	glog.Infof("UpdateUser: user " + oktaId + " usertype updated for tenant " + tenant)

	return nil
}

// Add a user to a Okta group
func AddToGroup(API string, TOKEN string, oktaGID string, oktaUID string, ulogin string, signup bool) error {
	_, client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		glog.Errorf("AddToGroup: failed to get client for user " + ulogin + "/" + oktaUID)
		return err
	}
	uid, err := CheckGroupUser(client, oktaGID, oktaUID, makeUserId(ulogin))
	if err == nil && signup {
		glog.Errorf("AddToGroup: found user " + oktaUID + " during signup")
		return err
	}
	if (err == nil && uid != oktaUID) || (err != nil) {
		_, err = client.Group.AddUserToGroup(context.TODO(), oktaGID, oktaUID)
		if err != nil {
			glog.Errorf("AddToGroup: user "+ulogin+"/"+oktaUID+" add to %s failed - %v", oktaGID, err)
			return err
		}
		glog.Infof("AddToGroup: user " + ulogin + "/" + oktaUID + " added to group " + oktaGID)
	}
	return nil
}

// Check if group has user, and if so, return user's Okta ID.
func CheckGroupUser(client *okta.Client, gid string, uid string, ulogin string) (string, error) {

	filter := query.NewQueryParams(query.WithFilter("profile.login eq \"" + makeUserId(ulogin) + "\""))
	u, _, err := client.Group.ListGroupUsers(context.TODO(), gid, filter)
	if err != nil {
		glog.Errorf("CheckGroupUser: user " + ulogin + "/" + uid + " search failed in group " + gid)
		return "", err
	}
	for _, usr := range u {
		if usr.Id == uid {
			// User is in group
			glog.Infof("CheckGroupUser: Found user " + ulogin + " in group " + gid)
			return usr.Id, nil
		}
	}
	glog.Infof("CheckGroupUser: user " + ulogin + "/" + uid + " not found in group " + gid)
	return "", errors.New("Group " + gid + " does not have user " + ulogin)
}

// Function that actually updates the custom attributes in the default user profile.
// All attributes that are not part of the default 31 attributes defined by Okta are
// added as custom attributes in the default user profile.
// Attributes are added if they don't exist, updated if they already exist.
func UpdDefaultUserCustomProfile(client *okta.Client, attrjson *[]byte) error {

	type ItemProp struct {
		Type  string   `bson:"type" json:"type"`
		Enums []string `bson:"enums" json:"enums"`
	}

	attrList := make(map[string]ItemProp, 0)
	err := json.Unmarshal(*attrjson, &attrList)
	if err != nil {
		glog.Errorf("UpdDefaultUserCustomProfile: attribute set unmarshal error - %v", err)
		return err
	}
	uschema, _, err := client.UserSchema.GetUserSchema(context.TODO(), "default")
	if err != nil {
		glog.Errorf("UpdDefaultUserCustomProfile: could not get user schema - %v", err)
		return err
	}
	customattrs := uschema.Definitions.Custom.Properties
	req := false
	acount := 0
	ucount := 0
	glog.Infof("UpdDefaultUserCustomProfile: received attributes %v", attrList)
	for attr, val := range attrList {
		cuattrProp, ok := customattrs[attr]
		attrType := strings.ToLower(val.Type)
		if !ok {
			// Attribute missing - add it
			perm := okta.UserSchemaAttributePermission{
				Principal: "SELF",
				Action:    "READ_WRITE",
			}
			items := okta.UserSchemaAttributeItems{}
			uattrProp := okta.UserSchemaAttribute{
				Description: attr,
				Title:       attr,
				Type:        attrType,
				Required:    &req,
				MaxLength:   0,
				MinLength:   0,
				Permissions: []*okta.UserSchemaAttributePermission{&perm},
			}
			switch attrType {
			case "string-array":
				uattrProp.Type = "array"
				attrEnums := val.Enums
				for _, enumVal := range attrEnums {
					enumSplit := strings.Split(enumVal, ":")
					items.Enum = append(items.Enum, enumSplit[0])
					items.OneOf = append(items.OneOf, &okta.UserSchemaAttributeEnum{Const: enumSplit[0], Title: enumSplit[1]})
					items.Type = "string"
				}
				uattrProp.Items = &items
			case "number-array":
				uattrProp.Type = "array"
				attrEnums := val.Enums
				for _, enumVal := range attrEnums {
					enumSplit := strings.Split(enumVal, ":")
					items.Enum = append(items.Enum, enumSplit[0])
					items.OneOf = append(items.OneOf, &okta.UserSchemaAttributeEnum{Const: enumSplit[0], Title: enumSplit[1]})
					items.Type = "string"
				}
				uattrProp.Items = &items
			default:
			}
			customattrs[attr] = &uattrProp
			acount++
		} else {
			// Attribute exists. Update just the Items field - Enums and OneOf.
			// Not sure how Okta handles the items.Type field.
			items := okta.UserSchemaAttributeItems{}
			switch attrType {
			case "string-array":
				attrEnums := val.Enums
				for _, enumVal := range attrEnums {
					enumSplit := strings.Split(enumVal, ":")
					items.Enum = append(items.Enum, enumSplit[0])
					items.OneOf = append(items.OneOf, &okta.UserSchemaAttributeEnum{Const: enumSplit[0], Title: enumSplit[1]})
					items.Type = "string"
				}
				cuattrProp.Items = &items
			case "number-array":
				attrEnums := val.Enums
				for _, enumVal := range attrEnums {
					enumSplit := strings.Split(enumVal, ":")
					items.Enum = append(items.Enum, enumSplit[0])
					items.OneOf = append(items.OneOf, &okta.UserSchemaAttributeEnum{Const: enumSplit[0], Title: enumSplit[1]})
					items.Type = "string"
				}
				cuattrProp.Items = &items
			default:
			}
			customattrs[attr] = cuattrProp
			ucount++
		}
	}
	_, _, err = client.UserSchema.UpdateUserProfile(context.TODO(), "default", *uschema)
	if err != nil {
		glog.Errorf("UpdDefaultUserCustomProfile: update failed - %v", err)
		return err
	}
	glog.Errorf("UpdDefaultUserCustomProfile: added %d, updated %d custom user profile attributes", acount, ucount)
	return nil
}

func setCustomUserAttr(client *okta.Client, tenant string, attrjson *[]byte) (string, error) {
	grpid, err := CheckGroup(client, tenant, false)
	if err != nil {
		glog.Errorf("SetCustomUserAttr: Could not find group for tenant " + tenant)
		return "", err
	}

	err = UpdDefaultUserCustomProfile(client, attrjson)
	if err != nil {
		glog.Errorf("SetCustomUserAttr: Could not update default user profile for tenant "+tenant+" - %v", err)
		return "", err
	}

	glog.Infof("SetCustomUserAttr: exported user attribute set for tenant " + tenant + " to Idp custom profile")
	return grpid, nil
}

// Export user attribute set for any tenant to Idp
func SetTenantCustomUserAttr(API string, TOKEN string, tenant string, attrjson *[]byte) (string, error) {
	// Get group for tenant
	// Get default user profile and add any new attributes / update existing ones
	// TODO: figure out how to remove obsolete attributes since such attributes
	// can be deleted from user profile only if not used by any tenant.

	_, client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		return "", err
	}
	return setCustomUserAttr(client, tenant, attrjson)
}

// Search for a specific user's attributes in a collection of attributes for all users
// The attribute collection is from nextensio.
func SearchUser(userattrs []primitive.M, uid string) primitive.M {
	for _, attrs := range userattrs {
		if attrs["uid"].(string) == uid {
			return attrs
		}
	}
	return nil
}

// This is for export of user attributes for a tenant from nextensio to Idp.
// The set of attributes is defined by the user AttrSet for the tenant in Nextensio.
// Nextensio holds attribute values for all users only for these attributes.
// If any new attributes have been defined in Nextensio and are missing in the Idp,
// they will be added in the Idp's user profile before the user attribute data is
// exported.
// This api is expected to be used when Nextensio is the source of truth for user data.
func SetAllUserAttr(API string, TOKEN string, tenant string, attrjson *[]byte, uattrval []byte) error {
	// Set tenant's missing user attributes in custom profile, if needed
	// Get users in Okta tenant group via ListGroupUsers()
	// For each user, set the attribute values.
	// attrjson is the user AttrSet in json form
	// uattrval is the collection of all users and their attributes as a json byte array

	var userattrs []primitive.M
	var oktausers map[string]bool

	_, client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		return err
	}
	grpid, err := setCustomUserAttr(client, tenant, attrjson)
	if err != nil {
		return err
	}

	users, _, err := client.Group.ListGroupUsers(context.TODO(), grpid, nil)
	if err != nil {
		glog.Errorf("SetAllUserAttr: Could not find any users in group for tenant "+tenant+" - %v", err)
		return err
	}

	err = json.Unmarshal(uattrval, &userattrs)
	if err != nil {
		glog.Errorf("SetAllUserAttr: Could not unmarshal user attributes for tenant "+tenant+" - %v", err)
		return err
	}

	ecount := 0 // error count
	ucount := 0 // update count
	mcount := 0 // missing users count - in Okta but missing in Nextensio
	errusers := []string{}
	misusers := []string{}
	oktausers = make(map[string]bool, 0)
	for _, guser := range users {
		// For each user in tenant group, get user info/profile
		userinfo, _, err := client.User.GetUser(context.TODO(), guser.Id)
		if err == nil {
			uprofile := *userinfo.Profile
			uid := uprofile["login"].(string)
			oktausers[uid] = true
			// Search for user attribute record in data from Nextensio
			nxtuser := SearchUser(userattrs, uid)
			if nxtuser == nil {
				// User is in Okta but not in Nextensio. Skip user.
				// This should not happen since we add a user to our
				// mongo collection and to Okta at the same time, unless
				// the add to Okta succeeded but the add to our mongo
				// collection somehow failed. We also delete the user from
				// Okta if we delete the user from Nextensio.
				// Let's log such errors but not take any corrective
				// action here.
				mcount++
				misusers = append(misusers, uid)
				continue
			}
			for key, val := range nxtuser {
				// For each user attribute from Nextensio, update
				// the attribute in the Okta user profile.
				if key == "uid" {
					continue
				}
				switch val.(type) {
				case []interface{}:
					uprofile[key] = val
				default:
					uprofile[key] = val
				}
			}
			userinfo.Profile = &uprofile
			_, _, err := client.User.UpdateUser(context.TODO(), guser.Id, *userinfo, nil)
			if err != nil {
				glog.Errorf("SetAllUserAttr: Okta update of exported attribute values failed for user %s - %v", uid, err)
				ecount++
				errusers = append(errusers, guser.Id)
			} else {
				ucount++
			}
		} else {
			// This should not happen since the user is from ListGroupUsers.
			// We'll just keep track as this would be very serious.
			ecount++
			errusers = append(errusers, guser.Id)
		}
	}
	if mcount > 0 {
		glog.Errorf("SetAllUserAttr: %d users in Okta not in Nextensio - %v", mcount, misusers)
	}
	if ecount > 0 {
		glog.Errorf("SetAllUserAttr: %d users could not be updated in Okta - %v", ecount, errusers)
	}
	// Find out if we have any users in Nextensio but not in Okta.
	// That should not happen since we add users to our mongo collection
	// only if we have successfully added the user to Okta first.
	// If we find any such users, we will log those users but not take
	// any corrective action here. It's possible such users may have been
	// removed from Okta via the dashboard but the removal hasn't happened
	// in Nextensio. It could be due to a process failure based on source
	// of truth for user data.
	omcount := 0 // count of Nextensio users missing from Okta
	misusers = []string{}
	for _, nxtval := range userattrs {
		// for each user attribute record from Nextensio
		nxtuid := nxtval["uid"].(string)
		_, ok := oktausers[nxtuid]
		if !ok {
			// User in Nextensio but not in Okta.
			omcount++
			misusers = append(misusers, nxtuid)
		}
	}
	if omcount > 0 {
		glog.Errorf("SetAllUserAttr: %d users in Nextensio not in Okta - %v", omcount, misusers)
	}
	glog.Infof("SetAllUserAttr: exported %d users with attributes to Okta, %d failed", ucount, ecount)
	return nil
}

// This is for import of user attributes for a tenant from Okta to Nextensio.
// The set of attributes is defined by the user AttrSet for the tenant in Nextensio
// (since we can't get the set of attributes for any tenant from Okta)
// This api is expected to be used when Okta is the source of truth for user data
// (Okta or an external entity from where Okta imports user data - LDAP/AD/Workday/Salesforce/...)
func GetAllUserAttr(API string, TOKEN string, tenant string, uattrNeeded []string) ([]byte, error) {
	// Get Okta group for tenant
	// Get users in group via ListGroupUsers()
	// For each user, get attribute values based on attributes in our AttrSet
	// Package all user attributes into an array and return a json byte array

	var allusers []map[string]interface{}
	var oneuser map[string]interface{}

	bytebody := []byte("")
	_, client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		glog.Errorf("GetAllUserAttr: Could not get client for tenant " + tenant)
		return bytebody, err
	}
	grpid, err := CheckGroup(client, tenant, false)
	if err != nil {
		glog.Errorf("GetAllUserAttr: Could not find group for tenant " + tenant)
		return bytebody, err
	}
	users, _, err := client.Group.ListGroupUsers(context.TODO(), grpid, nil)
	if err != nil {
		glog.Errorf("GetAllUserAttr: Could not find any users in group for tenant "+tenant+" - %v", err)
		return bytebody, err
	}
	glog.Infof("GetAllUserAttr: Found %d users in Idp group for tenant", len(users))
	allusers = make([]map[string]interface{}, 0)
	oneuser = make(map[string]interface{}, 0)
	ecount := 0
	acount := 0
	errusers := []string{}
	for _, guser := range users {
		userinfo, _, err := client.User.GetUser(context.TODO(), guser.Id)
		if err == nil {
			uprofile := *userinfo.Profile
			for _, key := range uattrNeeded {
				oneuser[key] = uprofile[key]
			}
			oneuser["uid"] = uprofile["login"].(string)
			allusers = append(allusers, oneuser)
			acount++
		} else {
			ecount++
			errusers = append(errusers, guser.Id)
		}
	}
	if ecount > 0 {
		glog.Errorf("GetAllUserAttr: failed for %d users - %v", ecount, errusers)
	} else {
		glog.Infof("GetAllUserAttr: importing attributes for %d users", acount)
	}
	bytebody, err = json.Marshal(allusers)
	if err != nil {
		glog.Errorf("GetAllUserAttr: Could not marshal attributes for users of tenant "+tenant+" - %v", err)
		return bytebody, err
	}
	return bytebody, nil
}

//-------------------------------------Group API functions-----------------------------------

// Check if group is valid/exists and if so, return its ID.
func CheckGroup(client *okta.Client, group string, delok bool) (string, error) {
	groupIds, _, err := client.Group.ListGroups(context.TODO(), query.NewQueryParams(query.WithQ(group)))
	if err != nil {
		glog.Errorf("CheckGroup: search for tenant %s group errored - %v", group, err)
		return "", err
	}
	if len(groupIds) != 1 {
		glog.Errorf("CheckGroup: None or Multiple groups for tenant " + group)
		if len(groupIds) > 1 && delok {
			for _, grp := range groupIds {
				_, err1 := client.Group.DeleteGroup(context.TODO(), grp.Id)
				glog.Infof("Deleting group %v - status: %v", *grp, err1)
			}
		}
		return "", errors.New("None or Multiple groups for tenant " + group)
	}
	glog.Infof("CheckGroup: Found tenant " + group + " group with id " + groupIds[0].Id)
	return groupIds[0].Id, nil
}

// Given a Group name, return the ID if group found
func GetGroupID(API string, TOKEN string, group string) (string, error) {
	_, client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		return "", err
	}

	return CheckGroup(client, group, false)
}

// Create a new group when a new tenant is created. Tenant creation may be via signup or via the
// tenant creation api. Group name given is the tenant name.
// Returns group ID assigned by Okta if successful.
func AddGroup(API string, TOKEN string, group string, signup bool) (string, error) {
	_, client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		glog.Errorf("AddGroup: Failed to get client - %v", err)
		return "", err
	}

	// Check if group already exists
	gid, err := CheckGroup(client, group, true)
	glog.Infof("AddGroup: checkgroup returned gid = %s, err = %v", gid, err)
	if err == nil && signup {
		return "", errors.New("Group " + group + " already exists")
	}
	if err != nil {
		gprofile := okta.GroupProfile{}
		gprofile.Name = group
		gprofile.Description = group
		grp := &okta.Group{
			Profile: &gprofile,
			Type:    "OKTA_GROUP",
		}
		g, _, err := client.Group.CreateGroup(context.TODO(), *grp)
		if err != nil {
			glog.Errorf("AddGroup: Group "+group+" could not be created - %v", err)
			return "", errors.New("Group " + group + " could not be created")
		}
		gid = g.Id
		glog.Infof("AddGroup: New group created for tenant " + group)
	} else {
		glog.Infof("AddGroup: group already exists for tenant " + group)
	}
	_ = AddAppsToGroup(client, gid, signup)
	return gid, nil
}

// Delete group when tenant is deleted.
func DelGroup(API string, TOKEN string, group string) error {
	_, client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		return err
	}

	// Get group ID
	gid, err := CheckGroup(client, group, true)
	if err != nil {
		// Group not unique
		glog.Errorf("DelGroup: group delete error for tenant "+group+" - %v", err)
		return nil
	}
	_, err = client.Group.DeleteGroup(context.TODO(), gid)
	glog.Infof("DelGroup: group delete for tenant "+group+" - %v", err)
	return err
}

// Add Nextensio Apps to a group. Need to filter out Okta apps.
func AddAppsToGroup(client *okta.Client, oktaGID string, signup bool) error {
	apps, _, err := client.Application.ListApplications(context.TODO(), nil)
	if err != nil {
		glog.Errorf("No Apps found - %v", err)
		return errors.New("No Apps found for adding to group ID " + oktaGID)
	}
	grpapps, _, err := client.Group.ListAssignedApplicationsForGroup(context.TODO(), oktaGID, nil)
	glog.Infof("Apps: %v\nGrpApps: %v", apps, grpapps)
	for i, app := range apps {
		glog.Infof("Apps[%d] Name: %s, ID: %s, Label: %s, Status: %s, Profile: %v", i,
			app.(*okta.Application).Name,
			app.(*okta.Application).Id,
			app.(*okta.Application).Label,
			app.(*okta.Application).Status,
			app.(*okta.Application).Profile)

		applbl := app.(*okta.Application).Label
		found := false
		for _, gapp := range grpapps {
			gapplbl := gapp.(*okta.Application).Label
			if applbl == gapplbl {
				found = true
				break
			}
		}
		if found {
			// App is already assigned to group, so skip
			glog.Infof("AddAppToGroup: " + applbl + " already assigned to group " + oktaGID)
			continue
		}
		if strings.HasPrefix(applbl, "Okta") {
			// Skip Okta apps
			glog.Infof("AddAppToGroup: " + applbl + " skipped - Okta App")
			continue
		}
		appid := app.(*okta.Application).Id
		appgrp := &okta.ApplicationGroupAssignment{}
		_, _, err = client.Application.CreateApplicationGroupAssignment(context.TODO(), appid, oktaGID, *appgrp)
		if err != nil {
			glog.Errorf("AddAppToGroup: Failed to add "+applbl+" to group "+oktaGID+" - %v", err)
			continue
		}
		glog.Infof("AddAppToGroup: Added " + applbl + " to group " + oktaGID)
	}
	return nil
}
