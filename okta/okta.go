package okta

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang/glog"
	"github.com/okta/okta-sdk-golang/okta"
	"github.com/okta/okta-sdk-golang/okta/query"
)

func makeUserId(userid string) string {
	return userid
}

func GetUser(API string, TOKEN string, userid string) (string, string, error) {
	search := fmt.Sprintf("profile.login eq \"%s\"", makeUserId(userid))
	client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		return "", "", err
	}
	filter := query.NewQueryParams(query.WithFilter(search))
	users, _, err := client.User.ListUsers(filter)
	if err != nil {
		return "", "", err
	}
	if len(users) != 1 {
		return "", "", err
	}
	return users[0].Id, (*users[0].Profile)["organization"].(string), nil
}

func AddUser(API string, TOKEN string, userid string, tenant string, userType string) (string, error) {
	client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		return "", err
	}
	oktaId, oktaTenant, e := GetUser(API, TOKEN, userid)
	if e == nil && oktaId != "" {
		if oktaTenant != tenant {
			return "", errors.New("User already assigned to another tenant")
		}
		e = UpdateUser(API, TOKEN, userid, tenant, userType)
		if e != nil {
			return "", e
		}
		return oktaId, nil
	} else {
		profile := okta.UserProfile{}
		profile["firstName"] = "Nextensio"
		profile["lastName"] = "Customer"
		profile["email"] = userid
		profile["login"] = makeUserId(userid)
		profile["organization"] = tenant
		profile["userType"] = userType
		u := &okta.User{
			Profile: &profile,
		}
		user, _, err := client.User.CreateUser(*u, nil)
		if err != nil {
			return "", err
		}
		return user.Id, nil
	}
}

func DelUser(API string, TOKEN string, userid string, tenant string) error {
	client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		return err
	}
	oktaId, oktaTenant, e := GetUser(API, TOKEN, userid)
	if e != nil {
		return e
	}
	if oktaTenant != tenant {
		glog.Errorf("user %s is part of tenant [%s], I am part of tenant[%s]", userid, oktaTenant, tenant)
		return errors.New("Cannot delete user belonging to another tenant")
	}
	_, err = client.User.DeactivateUser(oktaId, nil)
	if err != nil {
		return err
	}
	_, err = client.User.DeactivateOrDeleteUser(oktaId, nil)
	if err != nil {
		return err
	}

	return nil
}

func AddToGroup(API string, TOKEN string, oktaUID string, oktaGID string) error {
	client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		return err
	}
	_, err = client.Group.AddUserToGroup(oktaGID, oktaUID)
	if err != nil {
		return err
	}
	return nil
}

func GetGroup(API string, TOKEN string, group string) (string, error) {
	client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		return "", err
	}

	groupIds, _, err := client.Group.ListGroups(query.NewQueryParams(query.WithQ(group)))
	if err != nil {
		return "", err
	}
	if len(groupIds) != 1 {
		return "", errors.New("Group not found")
	}
	return groupIds[0].Id, nil
}

func UpdateUser(API string, TOKEN string, userid string, tenant string, userType string) error {
	client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		return err
	}
	oktaId, oktaTenant, err := GetUser(API, TOKEN, userid)
	if err != nil {
		return err
	}
	if oktaTenant != tenant {
		return errors.New("Cannot modify user beloging to another tenant")
	}
	user, _, err := client.User.GetUser(oktaId)
	if err != nil {
		return err
	}

	newProfile := *user.Profile
	newProfile["organization"] = tenant
	newProfile["userType"] = userType
	updatedUser := &okta.User{
		Profile: &newProfile,
	}
	_, _, err = client.User.UpdateUser(oktaId, *updatedUser, nil)
	if err != nil {
		return err
	}

	return nil
}
