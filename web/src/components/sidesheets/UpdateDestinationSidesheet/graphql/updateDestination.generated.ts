/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type UpdateDestinationVariables = {
  input: Types.DestinationInput;
};

export type UpdateDestination = {
  updateDestination: Types.Maybe<
    Pick<
      Types.Destination,
      | 'createdBy'
      | 'creationTime'
      | 'displayName'
      | 'lastModifiedBy'
      | 'lastModifiedTime'
      | 'outputId'
      | 'outputType'
      | 'verificationStatus'
      | 'defaultForSeverity'
    > & {
      outputConfig: {
        slack: Types.Maybe<Pick<Types.SlackConfig, 'webhookURL'>>;
        sns: Types.Maybe<Pick<Types.SnsConfig, 'topicArn'>>;
        pagerDuty: Types.Maybe<Pick<Types.PagerDutyConfig, 'integrationKey'>>;
        github: Types.Maybe<Pick<Types.GithubConfig, 'repoName' | 'token'>>;
        jira: Types.Maybe<
          Pick<
            Types.JiraConfig,
            'orgDomain' | 'projectKey' | 'userName' | 'apiKey' | 'assigneeId' | 'issueType'
          >
        >;
        opsgenie: Types.Maybe<Pick<Types.OpsgenieConfig, 'apiKey'>>;
        msTeams: Types.Maybe<Pick<Types.MsTeamsConfig, 'webhookURL'>>;
        sqs: Types.Maybe<Pick<Types.SqsConfig, 'queueUrl'>>;
        asana: Types.Maybe<Pick<Types.AsanaConfig, 'personalAccessToken' | 'projectGids'>>;
      };
    }
  >;
};

export const UpdateDestinationDocument = gql`
  mutation UpdateDestination($input: DestinationInput!) {
    updateDestination(input: $input) {
      createdBy
      creationTime
      displayName
      lastModifiedBy
      lastModifiedTime
      outputId
      outputType
      outputConfig {
        slack {
          webhookURL
        }
        sns {
          topicArn
        }
        pagerDuty {
          integrationKey
        }
        github {
          repoName
          token
        }
        jira {
          orgDomain
          projectKey
          userName
          apiKey
          assigneeId
          issueType
        }
        opsgenie {
          apiKey
        }
        msTeams {
          webhookURL
        }
        sqs {
          queueUrl
        }
        asana {
          personalAccessToken
          projectGids
        }
      }
      verificationStatus
      defaultForSeverity
    }
  }
`;
export type UpdateDestinationMutationFn = ApolloReactCommon.MutationFunction<
  UpdateDestination,
  UpdateDestinationVariables
>;

/**
 * __useUpdateDestination__
 *
 * To run a mutation, you first call `useUpdateDestination` within a React component and pass it any options that fit your needs.
 * When your component renders, `useUpdateDestination` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [updateDestination, { data, loading, error }] = useUpdateDestination({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useUpdateDestination(
  baseOptions?: ApolloReactHooks.MutationHookOptions<UpdateDestination, UpdateDestinationVariables>
) {
  return ApolloReactHooks.useMutation<UpdateDestination, UpdateDestinationVariables>(
    UpdateDestinationDocument,
    baseOptions
  );
}
export type UpdateDestinationHookResult = ReturnType<typeof useUpdateDestination>;
export type UpdateDestinationMutationResult = ApolloReactCommon.MutationResult<UpdateDestination>;
export type UpdateDestinationMutationOptions = ApolloReactCommon.BaseMutationOptions<
  UpdateDestination,
  UpdateDestinationVariables
>;
