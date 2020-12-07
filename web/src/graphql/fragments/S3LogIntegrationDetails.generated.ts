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

import * as Types from '../../../__generated__/schema';

import { IntegrationItemHealthDetails } from './IntegrationItemHealthDetails.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';

export type S3LogIntegrationDetails = Pick<
  Types.S3LogIntegration,
  | 'integrationId'
  | 'integrationLabel'
  | 'integrationType'
  | 'createdAtTime'
  | 'createdBy'
  | 'awsAccountId'
  | 'lastEventReceived'
  | 'kmsKey'
  | 's3Bucket'
  | 'stackName'
> & {
  s3PrefixLogTypes: Array<Pick<Types.S3PrefixLogTypes, 'prefix' | 'logTypes'>>;
  health: {
    processingRoleStatus: IntegrationItemHealthDetails;
    s3BucketStatus: IntegrationItemHealthDetails;
    kmsKeyStatus: IntegrationItemHealthDetails;
  };
};

export const S3LogIntegrationDetails = gql`
  fragment S3LogIntegrationDetails on S3LogIntegration {
    integrationId
    integrationLabel
    integrationType
    createdAtTime
    createdBy
    awsAccountId
    lastEventReceived
    kmsKey
    s3Bucket
    s3PrefixLogTypes {
      prefix
      logTypes
    }
    stackName
    health {
      processingRoleStatus {
        ...IntegrationItemHealthDetails
      }
      s3BucketStatus {
        ...IntegrationItemHealthDetails
      }
      kmsKeyStatus {
        ...IntegrationItemHealthDetails
      }
    }
  }
  ${IntegrationItemHealthDetails}
`;
