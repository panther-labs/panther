package main

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	cfn "github.com/aws/aws-sdk-go/service/cloudformation"
	provider "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const (
	backendStack         = "panther-bootstrap"
	userPoolIDOutputName = "UserPoolId"

	usersAPI     = "panther-users-api"
	systemUserID = "00000000-0000-4000-8000-000000000000"

	// The integration test will only create and delete resources with this prefix
	resourcePrefix = "integration-test-"
)

var (
	integrationTest bool
	awsSession      = session.Must(session.NewSession())
	lambdaClient    = lambda.New(awsSession)

	// fake user ID
	testUserID = "00000000-0000-4000-8000-000000000000"

	userPoolID *string
	aliceUser  models.User
	bobUser    models.User
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	os.Exit(m.Run())
}

// Remove all cognito users that were added by integration tests
func cleanUpCognitoUsers() error {
	var err error
	userPoolID, err = getUserPoolID()
	if err != nil {
		return err
	}

	// Find users whose email starts with the integration test prefix
	client := provider.New(awsSession)
	input := &provider.ListUsersInput{UserPoolId: userPoolID}
	var usernamesToDelete []*string
	err = client.ListUsersPages(input, func(page *provider.ListUsersOutput, isLast bool) bool {
		for _, u := range page.Users {
			for _, attr := range u.Attributes {
				if *attr.Name == "email" && strings.HasPrefix(*attr.Value, resourcePrefix) {
					usernamesToDelete = append(usernamesToDelete, u.Username)
					break
				}
			}
		}
		return true
	})
	if err != nil {
		return fmt.Errorf("list users for pool %s failed: %v", *userPoolID, err)
	}

	// Delete matching users
	for _, username := range usernamesToDelete {
		_, err = client.AdminDeleteUser(&provider.AdminDeleteUserInput{
			UserPoolId: userPoolID,
			Username:   username,
		})
		if err != nil {
			return fmt.Errorf("delete user %s failed: %v", *username, err)
		}
	}
	return nil
}

// Find the user pool ID from the backend stack outputs
func getUserPoolID() (*string, error) {
	cfnClient := cfn.New(awsSession)
	input := &cfn.DescribeStacksInput{StackName: aws.String(backendStack)}
	response, err := cfnClient.DescribeStacks(input)
	if err != nil {
		return nil, fmt.Errorf("describe stack failed: %v", err)
	}

	for _, output := range response.Stacks[0].Outputs {
		if aws.StringValue(output.OutputKey) == userPoolIDOutputName {
			return output.OutputValue, nil
		}
	}

	return nil, fmt.Errorf("%s output not found in stack %s", userPoolIDOutputName, backendStack)
}

// TestIntegrationAPI is the single integration test - invokes the live API Gateway.
func TestIntegrationAPI(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	// Clean up both before and after the integration test
	require.NoError(t, cleanUpCognitoUsers())
	defer func() { require.NoError(t, cleanUpCognitoUsers()) }()

	t.Run("InviteUser", func(t *testing.T) {
		t.Run("InviteUserAlice", testInviteUserAlice)
		t.Run("InviteUserBob", testInviteUserBob)
		t.Run("InviteUserInvalidRequester", testInviteUserInvalidRequester)
	})
	if t.Failed() {
		return
	}

	t.Run("GetUser", func(t *testing.T) {
		t.Run("GetUser", testGetUser)
		t.Run("GetUserDoesNotExist", testGetUserDoesNotExist)
	})

	t.Run("ListUsers", func(t *testing.T) {
		t.Run("ListUsers", testListUsers)
		t.Run("ListUsersNoMatch", testListUsersNoMatch)
		t.Run("ListUsersSortDescending", testListUsersSortDescending)
	})

	t.Run("UpdateUser", func(t *testing.T) {
		t.Run("UpdateUser", testUpdateUser)
		t.Run("UpdateUserDoesNotExist", testUpdateUserDoesNotExist)
	})

	// We don't trigger ResetUserPassword directly (which would send an email),
	// but we do test the Cognito custom message trigger that will happen in that flow.
	t.Run("CognitoTrigger", func(t *testing.T) {
		t.Run("CustomMessage", testCustomMessage)
		t.Run("UnknownTrigger", testUnknownTrigger)
	})

	t.Run("RemoveUser", func(t *testing.T) {
		t.Run("RemoveUser", testRemoveUser)
		t.Run("RemoveUserDoesNotExist", testRemoveUserDoesNotExist)
	})
}

func testInviteUserAlice(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		InviteUser: &models.InviteUserInput{
			RequesterID:   aws.String(systemUserID),
			GivenName:     aws.String("Alice"),
			FamilyName:    aws.String("Panther"),
			Email:         aws.String(resourcePrefix + "alice@runpanther.io"),
			MessageAction: aws.String("SUPPRESS"), // don't send a real invite email
		},
	}
	var output models.InviteUserOutput

	require.NoError(t, genericapi.Invoke(lambdaClient, usersAPI, &input, &output))
	assert.NotNil(t, output.CreatedAt)
	assert.NotNil(t, output.ID)
	expected := models.User{
		CreatedAt:  output.CreatedAt,
		Email:      input.InviteUser.Email,
		FamilyName: input.InviteUser.FamilyName,
		GivenName:  input.InviteUser.GivenName,
		ID:         output.ID,
		Status:     aws.String("FORCE_CHANGE_PASSWORD"),
	}
	require.Equal(t, expected, output)
	aliceUser = output
}

func testInviteUserBob(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		InviteUser: &models.InviteUserInput{
			RequesterID:   aws.String(systemUserID),
			GivenName:     aws.String("Bob"),
			FamilyName:    aws.String("Panther"),
			Email:         aws.String(resourcePrefix + "bob@runpanther.io"),
			MessageAction: aws.String("SUPPRESS"), // don't send a real invite email
		},
	}
	var output models.InviteUserOutput

	require.NoError(t, genericapi.Invoke(lambdaClient, usersAPI, &input, &output))
	assert.NotNil(t, output.CreatedAt)
	assert.NotNil(t, output.ID)
	expected := models.User{
		CreatedAt:  output.CreatedAt,
		Email:      input.InviteUser.Email,
		FamilyName: input.InviteUser.FamilyName,
		GivenName:  input.InviteUser.GivenName,
		ID:         output.ID,
		Status:     aws.String("FORCE_CHANGE_PASSWORD"),
	}
	require.Equal(t, expected, output)
	bobUser = output
}

func testInviteUserInvalidRequester(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		InviteUser: &models.InviteUserInput{
			// random requesterID - this user does not exist, so the request should be rejected
			RequesterID: aws.String("f3b71d8d-441b-4ce7-85e3-04cb531862cc"),

			GivenName:     aws.String("Chelsea"),
			FamilyName:    aws.String("Panther"),
			Email:         aws.String(resourcePrefix + "chelsea@runpanther.io"),
			MessageAction: aws.String("SUPPRESS"), // don't send a real invite email
		},
	}

	err := genericapi.Invoke(lambdaClient, usersAPI, &input, nil)
	require.Error(t, err)
	expected := &genericapi.LambdaError{
		ErrorMessage: aws.String(fmt.Sprintf(
			"failed to validate the user making the request: userID=%s does not exist",
			*input.InviteUser.RequesterID)),
		ErrorType:    aws.String("InvalidInputError"),
		FunctionName: usersAPI,
	}
	assert.Equal(t, expected, err)
}

func testGetUser(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		GetUser: &models.GetUserInput{ID: bobUser.ID},
	}

	var output models.GetUserOutput
	require.NoError(t, genericapi.Invoke(lambdaClient, usersAPI, &input, &output))
	assert.Equal(t, bobUser, output)
}

func testGetUserDoesNotExist(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		GetUser: &models.GetUserInput{ID: &testUserID}, // id does not exist
	}

	err := genericapi.Invoke(lambdaClient, usersAPI, &input, nil)
	require.Error(t, err)
	expected := &genericapi.LambdaError{
		ErrorMessage: aws.String("userID=" + testUserID + " does not exist"),
		ErrorType:    aws.String("DoesNotExistError"),
		FunctionName: usersAPI,
	}
	assert.Equal(t, expected, err)
}

func testListUsers(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListUsers: &models.ListUsersInput{
			Contains: aws.String(resourcePrefix),
			Status:   aws.String("FORCE_CHANGE_PASSWORD"),
		},
	}
	var output models.ListUsersOutput

	require.NoError(t, genericapi.Invoke(lambdaClient, usersAPI, &input, &output))
	expected := models.ListUsersOutput{
		// sort by emails ascending (alice < bob)
		Users: []models.User{aliceUser, bobUser},
	}
	assert.Equal(t, expected, output)
}

func testListUsersNoMatch(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListUsers: &models.ListUsersInput{
			Contains: aws.String(resourcePrefix),
			Status:   aws.String("NO_SUCH_STATUS"),
		},
	}
	var output models.ListUsersOutput

	require.NoError(t, genericapi.Invoke(lambdaClient, usersAPI, &input, &output))
	expected := models.ListUsersOutput{
		Users: []models.User{},
	}
	assert.Equal(t, expected, output)
}

func testListUsersSortDescending(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		ListUsers: &models.ListUsersInput{
			Contains: aws.String(resourcePrefix),
			SortBy:   aws.String("firstName"),
			SortDir:  aws.String("descending"),
		},
	}
	var output models.ListUsersOutput

	require.NoError(t, genericapi.Invoke(lambdaClient, usersAPI, &input, &output))
	expected := models.ListUsersOutput{
		// sort by name descending: bob > alice
		Users: []models.User{bobUser, aliceUser},
	}
	assert.Equal(t, expected, output)
}

func testUpdateUser(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		// only change last name
		UpdateUser: &models.UpdateUserInput{
			RequesterID: aws.String(systemUserID),
			ID:          aliceUser.ID,
			FamilyName:  aws.String("updated-family-name"),
		},
	}
	var output models.UpdateUserOutput

	require.NoError(t, genericapi.Invoke(lambdaClient, usersAPI, &input, &output))
	expected := aliceUser
	expected.FamilyName = input.UpdateUser.FamilyName
	require.Equal(t, expected, output)
	aliceUser = output
}

func testUpdateUserDoesNotExist(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		UpdateUser: &models.UpdateUserInput{
			RequesterID: aws.String(systemUserID),
			ID:          &testUserID, // no such user ID
			FamilyName:  aws.String("updated-family-name"),
		},
	}

	err := genericapi.Invoke(lambdaClient, usersAPI, &input, nil)
	require.Error(t, err)
	expected := &genericapi.LambdaError{
		ErrorMessage: aws.String("userID=" + testUserID + " does not exist"),
		ErrorType:    aws.String("DoesNotExistError"),
		FunctionName: usersAPI,
	}
	assert.Equal(t, expected, err)
}

// Invoke the users-api as if we are Cognito asking for the custom reset password email
func testCustomMessage(t *testing.T) {
	input := events.CognitoEventUserPoolsCustomMessage{
		CognitoEventUserPoolsHeader: events.CognitoEventUserPoolsHeader{
			TriggerSource: "CustomMessage_ForgotPassword",
			UserName:      *bobUser.ID,
		},
		Request: events.CognitoEventUserPoolsCustomMessageRequest{
			CodeParameter: "123456",
			UserAttributes: map[string]interface{}{
				"email":       *bobUser.Email,
				"family_name": *bobUser.FamilyName,
				"given_name":  *bobUser.GivenName,
			},
		},
	}
	var output events.CognitoEventUserPoolsCustomMessage

	require.NoError(t, genericapi.Invoke(lambdaClient, usersAPI, &input, &output))
	assert.Equal(t, "Panther Password Reset", output.Response.EmailSubject)
	assert.Contains(t, output.Response.EmailMessage,
		fmt.Sprintf("password-reset?token=%s&email=%s",
			input.Request.CodeParameter, url.QueryEscape(*bobUser.Email)))
}

// If users-api is invoked with an unexpected Cognito trigger, it just returns the event unmodified
func testUnknownTrigger(t *testing.T) {
	input := events.CognitoEventUserPoolsCustomMessage{
		CognitoEventUserPoolsHeader: events.CognitoEventUserPoolsHeader{
			TriggerSource: "NoSuchTrigger",
			UserName:      *bobUser.ID,
		},
	}
	var output events.CognitoEventUserPoolsCustomMessage

	require.NoError(t, genericapi.Invoke(lambdaClient, usersAPI, &input, &output))
	assert.Equal(t, output, input)
}

func testRemoveUser(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		RemoveUser: &models.RemoveUserInput{
			RequesterID: aws.String(systemUserID),
			ID:          bobUser.ID,
		},
	}
	var output models.RemoveUserOutput
	require.NoError(t, genericapi.Invoke(lambdaClient, usersAPI, &input, &output))
	assert.Equal(t, models.RemoveUserOutput{ID: input.RemoveUser.ID}, output)

	// Trying to get bob is now an error
	input = models.LambdaInput{
		GetUser: &models.GetUserInput{ID: bobUser.ID},
	}
	require.Error(t, genericapi.Invoke(lambdaClient, usersAPI, &input, nil))
}

func testRemoveUserDoesNotExist(t *testing.T) {
	t.Parallel()
	input := models.LambdaInput{
		RemoveUser: &models.RemoveUserInput{
			RequesterID: aws.String(systemUserID),
			ID:          &testUserID, // does not exist
		},
	}

	// No error trying to remove a user which has already been deleted
	require.NoError(t, genericapi.Invoke(lambdaClient, usersAPI, &input, nil))
}
