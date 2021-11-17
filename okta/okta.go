package okta

import (
	"context"
	"errors"
	"strings"

	"github.com/golang/glog"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
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
	oktaGid, err := CheckGroup(client, tenant)
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
	// Need to add filter
	//search := fmt.Sprintf("profile.login eq \"%s\"", makeUserId(ulogin))
	filter := query.NewQueryParams(query.WithFilter("profile.login eq \"" + ulogin + "\""))
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

//-------------------------------------Group API functions-----------------------------------

// Check if group is valid/exists and if so, return its ID.
func CheckGroup(client *okta.Client, group string) (string, error) {
	groupIds, _, err := client.Group.ListGroups(context.TODO(), query.NewQueryParams(query.WithQ(group)))
	if err != nil {
		glog.Errorf("CheckGroup: search for tenant %s group errored - %v", group, err)
		return "", err
	}
	if len(groupIds) != 1 {
		glog.Errorf("CheckGroup: None or Multiple groups for tenant " + group)
		if len(groupIds) > 1 {
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

	return CheckGroup(client, group)
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
	gid, err := CheckGroup(client, group)
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
	gid, err := CheckGroup(client, group)
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
