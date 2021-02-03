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

import * as Types from '../../../../__generated__/schema';

import { RuleSummary } from '../../../graphql/fragments/RuleSummary.generated';
import { PolicySummary } from '../../../graphql/fragments/PolicySummary.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListDetectionsVariables = {
  input?: Types.Maybe<Types.ListDetectionsInput>;
};

export type ListDetections = {
  detections: {
    detections: Array<PolicySummary | RuleSummary>;
    paging: Pick<Types.PagingData, 'totalPages' | 'thisPage' | 'totalItems'>;
  };
};

export const ListDetectionsDocument = gql`
  query ListDetections($input: ListDetectionsInput) {
    detections(input: $input) {
      detections {
        ... on Rule {
          ...RuleSummary
        }
        ... on Policy {
          ...PolicySummary
        }
      }
      paging {
        totalPages
        thisPage
        totalItems
      }
    }
  }
  ${RuleSummary}
  ${PolicySummary}
`;

/**
 * __useListDetections__
 *
 * To run a query within a React component, call `useListDetections` and pass it any options that fit your needs.
 * When your component renders, `useListDetections` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListDetections({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useListDetections(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListDetections, ListDetectionsVariables>
) {
  return ApolloReactHooks.useQuery<ListDetections, ListDetectionsVariables>(
    ListDetectionsDocument,
    baseOptions
  );
}
export function useListDetectionsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ListDetections, ListDetectionsVariables>
) {
  return ApolloReactHooks.useLazyQuery<ListDetections, ListDetectionsVariables>(
    ListDetectionsDocument,
    baseOptions
  );
}
export type ListDetectionsHookResult = ReturnType<typeof useListDetections>;
export type ListDetectionsLazyQueryHookResult = ReturnType<typeof useListDetectionsLazyQuery>;
export type ListDetectionsQueryResult = ApolloReactCommon.QueryResult<
  ListDetections,
  ListDetectionsVariables
>;
export function mockListDetections({
  data,
  variables,
  errors,
}: {
  data: ListDetections;
  variables?: ListDetectionsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: ListDetectionsDocument, variables },
    result: { data, errors },
  };
}
