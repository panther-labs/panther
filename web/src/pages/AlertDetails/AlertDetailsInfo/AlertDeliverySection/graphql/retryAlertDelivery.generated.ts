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

import * as Types from '../../../../../../__generated__/schema';

import { DeliveryResponseFull } from '../../../../../graphql/fragments/DeliveryResponseFull.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type RetryAlertDeliveryVariables = {
  input: Types.DeliverAlertInput;
};

export type RetryAlertDelivery = {
  deliverAlert: Pick<Types.AlertSummary, 'alertId'> & {
    deliveryResponses: Array<Types.Maybe<DeliveryResponseFull>>;
  };
};

export const RetryAlertDeliveryDocument = gql`
  mutation RetryAlertDelivery($input: DeliverAlertInput!) {
    deliverAlert(input: $input) {
      alertId
      deliveryResponses {
        ...DeliveryResponseFull
      }
    }
  }
  ${DeliveryResponseFull}
`;
export type RetryAlertDeliveryMutationFn = ApolloReactCommon.MutationFunction<
  RetryAlertDelivery,
  RetryAlertDeliveryVariables
>;

/**
 * __useRetryAlertDelivery__
 *
 * To run a mutation, you first call `useRetryAlertDelivery` within a React component and pass it any options that fit your needs.
 * When your component renders, `useRetryAlertDelivery` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [retryAlertDelivery, { data, loading, error }] = useRetryAlertDelivery({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useRetryAlertDelivery(
  baseOptions?: ApolloReactHooks.MutationHookOptions<
    RetryAlertDelivery,
    RetryAlertDeliveryVariables
  >
) {
  return ApolloReactHooks.useMutation<RetryAlertDelivery, RetryAlertDeliveryVariables>(
    RetryAlertDeliveryDocument,
    baseOptions
  );
}
export type RetryAlertDeliveryHookResult = ReturnType<typeof useRetryAlertDelivery>;
export type RetryAlertDeliveryMutationResult = ApolloReactCommon.MutationResult<RetryAlertDelivery>;
export type RetryAlertDeliveryMutationOptions = ApolloReactCommon.BaseMutationOptions<
  RetryAlertDelivery,
  RetryAlertDeliveryVariables
>;
export function mockRetryAlertDelivery({
  data,
  variables,
  errors,
}: {
  data: RetryAlertDelivery;
  variables?: RetryAlertDeliveryVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: RetryAlertDeliveryDocument, variables },
    result: { data, errors },
  };
}
