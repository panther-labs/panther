/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListDestinationsAndDefaultsVariables = {};

export type ListDestinationsAndDefaults = {
  destinations: Types.Maybe<
    Array<
      Types.Maybe<
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
      >
    >
  >;
};

export const ListDestinationsAndDefaultsDocument = gql`
  query ListDestinationsAndDefaults {
    destinations {
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

/**
 * __useListDestinationsAndDefaults__
 *
 * To run a query within a React component, call `useListDestinationsAndDefaults` and pass it any options that fit your needs.
 * When your component renders, `useListDestinationsAndDefaults` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListDestinationsAndDefaults({
 *   variables: {
 *   },
 * });
 */
export function useListDestinationsAndDefaults(
  baseOptions?: ApolloReactHooks.QueryHookOptions<
    ListDestinationsAndDefaults,
    ListDestinationsAndDefaultsVariables
  >
) {
  return ApolloReactHooks.useQuery<
    ListDestinationsAndDefaults,
    ListDestinationsAndDefaultsVariables
  >(ListDestinationsAndDefaultsDocument, baseOptions);
}
export function useListDestinationsAndDefaultsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    ListDestinationsAndDefaults,
    ListDestinationsAndDefaultsVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<
    ListDestinationsAndDefaults,
    ListDestinationsAndDefaultsVariables
  >(ListDestinationsAndDefaultsDocument, baseOptions);
}
export type ListDestinationsAndDefaultsHookResult = ReturnType<
  typeof useListDestinationsAndDefaults
>;
export type ListDestinationsAndDefaultsLazyQueryHookResult = ReturnType<
  typeof useListDestinationsAndDefaultsLazyQuery
>;
export type ListDestinationsAndDefaultsQueryResult = ApolloReactCommon.QueryResult<
  ListDestinationsAndDefaults,
  ListDestinationsAndDefaultsVariables
>;
