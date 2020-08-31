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

import { ComplianceIntegrationDetails } from '../../../graphql/fragments/ComplianceIntegrationDetails.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type AddComplianceSourceVariables = {
  input: Types.AddComplianceIntegrationInput;
};

export type AddComplianceSource = {
  addComplianceIntegration: { __typename: 'ComplianceIntegration' } & ComplianceIntegrationDetails;
};

export const AddComplianceSourceDocument = gql`
  mutation AddComplianceSource($input: AddComplianceIntegrationInput!) {
    addComplianceIntegration(input: $input) {
      ...ComplianceIntegrationDetails
      __typename
    }
  }
  ${ComplianceIntegrationDetails}
`;
export type AddComplianceSourceMutationFn = ApolloReactCommon.MutationFunction<
  AddComplianceSource,
  AddComplianceSourceVariables
>;

/**
 * __useAddComplianceSource__
 *
 * To run a mutation, you first call `useAddComplianceSource` within a React component and pass it any options that fit your needs.
 * When your component renders, `useAddComplianceSource` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [addComplianceSource, { data, loading, error }] = useAddComplianceSource({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useAddComplianceSource(
  baseOptions?: ApolloReactHooks.MutationHookOptions<
    AddComplianceSource,
    AddComplianceSourceVariables
  >
) {
  return ApolloReactHooks.useMutation<AddComplianceSource, AddComplianceSourceVariables>(
    AddComplianceSourceDocument,
    baseOptions
  );
}
export type AddComplianceSourceHookResult = ReturnType<typeof useAddComplianceSource>;
export type AddComplianceSourceMutationResult = ApolloReactCommon.MutationResult<
  AddComplianceSource
>;
export type AddComplianceSourceMutationOptions = ApolloReactCommon.BaseMutationOptions<
  AddComplianceSource,
  AddComplianceSourceVariables
>;
export function mockAddComplianceSource({
  data,
  variables,
  errors,
}: {
  data: AddComplianceSource;
  variables?: AddComplianceSourceVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: AddComplianceSourceDocument, variables },
    result: { data, errors },
  };
}
