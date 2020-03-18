/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../__generated__/schema';

import { IntegrationItemHealthDetails } from './IntegrationItemHealthDetails.generated';
import gql from 'graphql-tag';

export type ComplianceIntegrationDetails = Pick<
  Types.ComplianceIntegration,
  | 'integrationId'
  | 'integrationLabel'
  | 'awsAccountId'
  | 'createdAtTime'
  | 'createdBy'
  | 'cweEnabled'
  | 'remediationEnabled'
> & {
  health: {
    auditRoleStatus: IntegrationItemHealthDetails;
    cweRoleStatus: IntegrationItemHealthDetails;
    remediationRoleStatus: IntegrationItemHealthDetails;
  };
};

export const ComplianceIntegrationDetails = gql`
  fragment ComplianceIntegrationDetails on ComplianceIntegration {
    integrationId
    integrationLabel
    awsAccountId
    createdAtTime
    createdBy
    cweEnabled
    remediationEnabled
    health {
      auditRoleStatus {
        ...IntegrationItemHealthDetails
      }
      cweRoleStatus {
        ...IntegrationItemHealthDetails
      }
      remediationRoleStatus {
        ...IntegrationItemHealthDetails
      }
    }
  }
  ${IntegrationItemHealthDetails}
`;
