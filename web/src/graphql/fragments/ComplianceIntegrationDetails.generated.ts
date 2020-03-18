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
