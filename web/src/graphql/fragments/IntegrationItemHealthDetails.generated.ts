/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../__generated__/schema';

import gql from 'graphql-tag';

export type IntegrationItemHealthDetails = Pick<
  Types.IntegrationItemHealthStatus,
  'healthy' | 'errorMessage'
>;

export const IntegrationItemHealthDetails = gql`
  fragment IntegrationItemHealthDetails on IntegrationItemHealthStatus {
    healthy
    errorMessage
  }
`;
