package okta

import (
	"context"
	"errors"
	"fmt"

	"github.com/okta/okta-sdk-golang/okta"
	"github.com/okta/okta-sdk-golang/okta/query"
)

func makeUserId(userid string, tenant string) string {
	return userid
}

func GetUser(API string, TOKEN string, userid string, tenant string) (string, error) {
	search := fmt.Sprintf("profile.login eq \"%s\"", makeUserId(userid, tenant))
	client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		return "", err
	}
	filter := query.NewQueryParams(query.WithFilter(search))
	users, _, err := client.User.ListUsers(filter)
	if err != nil {
		return "", err
	}
	if len(users) != 1 {
		return "", err
	}
	return users[0].Id, nil
}

func AddUser(API string, TOKEN string, userid string, tenant string, userType string) (string, error) {
	client, err := okta.NewClient(context.TODO(), okta.WithOrgUrl(API), okta.WithToken(TOKEN))
	if err != nil {
		return "", err
	}
	oktaId, e := GetUser(API, TOKEN, userid, tenant)
	if e == nil && oktaId != "" {
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
		profile["login"] = makeUserId(userid, tenant)
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
	oktaId, e := GetUser(API, TOKEN, userid, tenant)
	if e != nil {
		return e
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
	oktaId, err := GetUser(API, TOKEN, userid, tenant)
	if err != nil {
		return err
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