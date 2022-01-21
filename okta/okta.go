package okta

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"nextensio/controller/db"
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

	oktaTenant := ""
	oktaUserType := "regular"
	if val, ok := (*users[0].Profile)["organization"]; ok {
		oktaTenant = val.(string)
	}
	if val, ok := (*users[0].Profile)["userType"]; ok {
		oktaUserType = val.(string)
	}
	return users[0].Id, oktaTenant, oktaUserType, nil
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
		if oktaTenant != "" && oktaTenant != tenant {
			glog.Errorf("User " + userid + "/" + oktaId + " exists but tenant mismatch " + tenant + "/" + oktaTenant)
			return "", errors.New("User already assigned to another tenant")
		}
		if (userType == "superadmin") && (oktaUsertype != "superadmin") {
			glog.Errorf("User " + userid + "/" + oktaId + " type cannot be upgraded to superadmin")
			return "", errors.New("User type cannot be upgraded to superadmin")
		}
		if (userType != "superadmin") && (oktaUsertype == "superadmin") {
			glog.Errorf("User " + userid + "/" + oktaId + " type cannot be downgraded from superadmin")
			return "", errors.New("User type cannot be downgraded from superadmin")
		}
		e = UpdateUser(client, userid, tenant, userType)
		if e != nil {
			glog.Errorf("User update failed for " + userid + "/" + oktaId)
			return "", e
		}
		glog.Infof("User " + userid + " updated to usertype " + userType)
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

// Get users of a tenant for a specific usertype
func GetUsersByType(API string, TOKEN string, tenant string, usertype string) ([]string, error) {
	var users []string
	_, client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		glog.Errorf("GetUsersByType: failed to get client - %v", err)
		return users, err
	}
	gid, err := CheckGroup(client, tenant)
	if err != nil {
		glog.Errorf("GetUsersByType: checkgroup for tenant %s returned error - %v", tenant, err)
		return users, err
	}
	return GetGroupUsersByType(client, gid, usertype)
}

// Group here refers to an Okta group which represents a tenant.
// This is a generic low-level function to get users of a tenant by usertype
func GetGroupUsersByType(client *okta.Client, gid string, usertype string) ([]string, error) {
	var users []string
	// Need to add filter
	// TODO: figure out why filter on userType is not working. Until then, we get all
	// users in group and filter later when adding to the users array.
	//filter := query.NewQueryParams(query.WithFilter("profile.userType eq \"" + utype + "\""))
	//usrlist, _, err := client.Group.ListGroupUsers(context.TODO(), gid, filter)
	usrlist, _, err := client.Group.ListGroupUsers(context.TODO(), gid, nil)
	if err != nil {
		glog.Errorf("GetGroupUsersByType: search failed in group %s for usertype %s - %v", gid, usertype, err)
		return users, err
	}
	for _, usr := range usrlist {
		if (*usr.Profile)["userType"].(string) == usertype {
			users = append(users, (*usr.Profile)["login"].(string))
		}
	}
	cnt := len(users)
	glog.Infof("GetGroupUsersByType: found %d users in group %s with usertype %s", cnt, gid, usertype)
	return users, nil
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
	err = AddAppsToGroup(client, gid, signup)
	return gid, err
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
	if err != nil {
		glog.Info("Cannot list groups", oktaGID)
		return err
	}
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
			// TODO: We should be returning error here instead of continuing, but
			// what we have seen is that even after we delete an app from okta, this
			// API somehow finds that app and then sys it cant add the app to this group
			// (because its deleted!). Till we find an answer for that we are just continuing
			glog.Errorf("AddAppToGroup: Failed to add "+applbl+" to group "+oktaGID+" - %v", err)
			continue
		}
		glog.Infof("AddAppToGroup: Added " + applbl + " to group " + oktaGID)
	}
	return nil
}

func createIdentityProvider(idpj *db.IDP) (*okta.IdentityProvider, error) {
	jwt := ""
	if idpj.Jwks != "" {
		jwt = `
		"jwks": {
			"binding": "HTTP-REDIRECT",
			"url": "` + idpj.Jwks + `"
		},
		`
	}
	iss := ""
	if idpj.Issuer != "" {
		iss = `
		"issuer": {
			"url": "` + idpj.Issuer + `"
		},
		`
	}
	jsonIDP := `
		{
			"name": "` + idpj.Name + `",
			"policy": {
				"accountLink": {
				  "action": "AUTO",
				  "filter": {
                    "groups": {
                        "include": [
                            "` + idpj.Group + `"
                        ]
                    }
                  }
				},
				"maxClockSkew": 0,
				"provisioning": {
				  "action": "AUTO",
				  "conditions": {
					"deprovisioned": {
					  "action": "NONE"
					},
					"suspended": {
					  "action": "NONE"
					}
				  },
				  "groups": {
					  "action": "ASSIGN",
					  "assignments": [
						  "` + idpj.Group + `"
					  ]
				  },
				  "profileMaster": false
				},
				"subject": {
				  "filter": null,
				  "matchAttribute": "",
				  "matchType": "USERNAME",
				  "userNameTemplate": {
					"template": "idpuser.email"
				  }
				}
			},  
			"protocol": {
			  "credentials": {
				  "client": {
					"client_id": "` + idpj.Client + `",
					"client_secret": "` + idpj.Secret + `"
				  }
			  },
			  "endpoints": {
				"authorization": {
				  "binding": "HTTP-REDIRECT",
				  "url": "` + idpj.Auth + `"
				},
				` + jwt + `
				"token": {
				  "binding": "HTTP-POST",
				  "url": "` + idpj.Token + `"
				}
			  },
			  ` + iss + `
			  "scopes": [
				"openid",
				"profile",
				"email"
			  ],
			  "type": "OIDC"
			},
			"status": "ACTIVE",
			"type": "OIDC"	
		}
	`

	var idp okta.IdentityProvider

	err := json.Unmarshal([]byte(jsonIDP), &idp)
	if err != nil {
		glog.Infof("Error unmarshalling policy json")
		return nil, err
	}

	return &idp, nil
}

func updateProfileMap(client *okta.Client, idpId string) error {
	params := query.NewQueryParams(query.WithSourceId(idpId))
	maps, _, err := client.ProfileMapping.ListProfileMappings(context.TODO(), params)
	if err != nil {
		glog.Infof("Profile mapping id get failed", err)
		return err
	}
	if len(maps) != 1 {
		glog.Infof("Profile mapping id get invalid", len(maps))
		return errors.New("invalid profile map")
	}
	m, _, err := client.ProfileMapping.GetProfileMapping(context.TODO(), maps[0].Id)
	if err != nil {
		glog.Infof("Profile mapping  get failed", err)
		return err
	}
	// Okta is anal about needing firstName and lastName from the external OIDC when
	// it does the JIT (Just In Time) creation of users when the login the first  time.
	// Not everyone returns those in the idToken, and sometimes ive seen even when its
	// returned in the idToken, okta still complains of missing first/last names and fails
	// JIT. We dont really care about these fields in okta, just fill it with email, which
	// we know all OIDCs will give us (scope email will usually be allowed)
	for k, _ := range m.Properties {
		if k == "firstName" {
			m.Properties[k].Expression = "appuser.email"
		}
		if k == "lastName" {
			m.Properties[k].Expression = "appuser.email"
		}
	}
	_, _, err = client.ProfileMapping.UpdateProfileMapping(context.TODO(), maps[0].Id, *m)
	if err != nil {
		glog.Infof("Profile mapping  get failed", err)
		return err
	}

	return nil
}

func CreateIDP(API string, TOKEN string, idpj *db.IDP) (string, string, error) {
	_, client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		glog.Infof("Cant get client", err)
		return "", "", err
	}

	params := query.Params{Type: "IDP_DISCOVERY"}
	policies, _, err := client.Policy.ListPolicies(context.TODO(), &params)
	if err != nil {
		glog.Infof("Cant get policies", err)
		return "", "", err
	}
	policyId := ""
	for _, p := range policies {
		if p.Type == "IDP_DISCOVERY" {
			policyId = p.Id
			break
		}
	}
	if policyId == "" {
		glog.Infof("Cant find IDP_DISCOVERY policy")
		return "", "", errors.New("cant find idp_discovery policy")
	}
	idp, err := createIdentityProvider(idpj)
	if err != nil {
		return "", "", err
	}
	resultIpd, _, err := client.IdentityProvider.CreateIdentityProvider(context.TODO(), *idp)
	if err != nil {
		glog.Infof("Error creating identity provider", err)
		return "", "", err
	}

	policy, err := createIDPPolicyRulePost(API, TOKEN, idpj.Name, resultIpd.Id, policyId, idpj.Domain)
	if err != nil {
		glog.Infof("IDP Policy failure")
		ierr := deleteIDPid(client, resultIpd.Id)
		if ierr != nil {
			glog.Infof("Attempt IDP deleteion, that too failed", ierr)
		}
		return "", "", err
	}

	err = updateProfileMap(client, resultIpd.Id)
	if err != nil {
		glog.Infof("IDP Mapping failure", err)
		ierr := deleteIDPid(client, resultIpd.Id)
		if ierr != nil {
			glog.Infof("Attempt IDP deleteion, that too failed", ierr)
		}
		return "", "", err
	}

	return resultIpd.Id, policy, nil
}

type PolicyRuleResp struct {
	Id string `json:"id" bson:"id"`
}

// The Okta API for PolicyCreate does not have the idp: proviers [...] capability yet, when they have it
// we can just switch back to the API version
func createIDPPolicyRulePost(API string, TOKEN string, name string, idpId string, policyId string, domain string) (string, error) {

	jsonRule := []byte(`
	{
        "actions": {
            "idp": {
                "providers": [
                    {
                        "id": "` + idpId + `",
                        "type": "OIDC"
                    }
                ]
            }
        },
        "conditions": {
            "app": {
                "exclude": [],
                "include": []
            },
            "network": {
                "connection": "ANYWHERE"
            },
            "platform": {
                "exclude": [],
                "include": [
                    {
                        "os": {
                            "type": "ANY"
                        },
                        "type": "ANY"
                    }
                ]
            },
            "userIdentifier": {
                "patterns": [
                    {
                        "matchType": "SUFFIX",
                        "value": "` + domain + `"
                    }
                ],
                "type": "IDENTIFIER"
            }
        },
        "name": "` + name + `",
        "priority": 1,
        "status": "ACTIVE",
        "system": false,
        "type": "IDP_DISCOVERY"
    }
	`)

	url := API + "/api/v1/policies/" + policyId + "/rules"
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonRule))
	if err != nil {
		glog.Errorf("Policy rule http create fail: " + err.Error())
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "SSWS "+TOKEN)

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		glog.Errorf("Policy rule http request fail: " + err.Error())
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		glog.Error("Response is not 200: " + response.Status)
		return "", errors.New("Bad response " + response.Status)
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		glog.Errorf("Policy create http response fail: " + err.Error())
		return "", err
	}
	var data PolicyRuleResp
	err = json.Unmarshal(body, &data)
	if err != nil {
		glog.Errorf("Error parsing policy rule response: " + err.Error())
		return "", err
	}

	return data.Id, nil
}

func createIDPPolicyRuleAPI(client *okta.Client, name string, idpId string, policyId string, domain string) (string, error) {

	jsonRule := `
	{
        "actions": {
            "idp": {
                "providers": [
                    {
                        "id": "` + idpId + `",
                        "type": "OIDC"
                    }
                ]
            }
        },
        "conditions": {
            "app": {
                "exclude": [],
                "include": []
            },
            "network": {
                "connection": "ANYWHERE"
            },
            "platform": {
                "exclude": [],
                "include": [
                    {
                        "os": {
                            "type": "ANY"
                        },
                        "type": "ANY"
                    }
                ]
            },
            "userIdentifier": {
                "patterns": [
                    {
                        "matchType": "SUFFIX",
                        "value": "` + domain + `"
                    }
                ],
                "type": "IDENTIFIER"
            }
        },
        "name": "` + name + `",
        "priority": 1,
        "status": "ACTIVE",
        "system": false,
        "type": "IDP_DISCOVERY"
    }
	`

	var policy okta.PolicyRule

	err := json.Unmarshal([]byte(jsonRule), &policy)
	if err != nil {
		glog.Infof("Error unmarshalling policy json")
		return "", err
	}

	p, _, err := client.Policy.CreatePolicyRule(context.TODO(), policyId, policy)
	if err != nil {
		glog.Infof("Error creating policy", err)
		return "", err
	}

	return p.Id, nil
}

func deleteIDPid(client *okta.Client, idpId string) error {
	return nil
}

func deletePolicyRule(client *okta.Client, policyId string) error {
	return nil
}

func DeleteIDP(API string, TOKEN string, idpj *db.IDP) error {
	_, client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		return err
	}

	err = deleteIDPid(client, idpj.Idp)
	if err != nil {
		return err
	}

	err = deletePolicyRule(client, idpj.Policy)
	if err != nil {
		return err
	}

	return nil
}
