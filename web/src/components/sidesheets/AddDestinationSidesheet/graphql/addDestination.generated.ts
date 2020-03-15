/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type AddDestinationVariables = {
  input: Types.DestinationInput;
};

export type AddDestination = {
  addDestination: Types.Maybe<
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

export const AddDestinationDocument = gql`
  mutation AddDestination($input: DestinationInput!) {
    addDestination(input: $input) {
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
export type AddDestinationMutationFn = ApolloReactCommon.MutationFunction<
  AddDestination,
  AddDestinationVariables
>;

/**
 * __useAddDestination__
 *
 * To run a mutation, you first call `useAddDestination` within a React component and pass it any options that fit your needs.
 * When your component renders, `useAddDestination` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [addDestination, { data, loading, error }] = useAddDestination({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useAddDestination(
  baseOptions?: ApolloReactHooks.MutationHookOptions<AddDestination, AddDestinationVariables>
) {
  return ApolloReactHooks.useMutation<AddDestination, AddDestinationVariables>(
    AddDestinationDocument,
    baseOptions
  );
}
export type AddDestinationHookResult = ReturnType<typeof useAddDestination>;
export type AddDestinationMutationResult = ApolloReactCommon.MutationResult<AddDestination>;
export type AddDestinationMutationOptions = ApolloReactCommon.BaseMutationOptions<
  AddDestination,
  AddDestinationVariables
>;
