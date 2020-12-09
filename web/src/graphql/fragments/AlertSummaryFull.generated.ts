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

import { DeliveryResponseFull } from './DeliveryResponseFull.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';

export type AlertSummaryFull = Pick<
  Types.AlertSummary,
  | 'alertId'
  | 'title'
  | 'severity'
  | 'type'
  | 'status'
  | 'creationTime'
  | 'updateTime'
  | 'lastUpdatedBy'
  | 'lastUpdatedByTime'
> & {
  deliveryResponses: Array<Types.Maybe<DeliveryResponseFull>>;
  detection:
    | Pick<Types.AlertSummaryRuleInfo, 'ruleId' | 'logTypes' | 'eventsMatched'>
    | Pick<
        Types.AlertSummaryPolicyInfo,
        'policyId' | 'resourceTypes' | 'resourceId' | 'policySourceId'
      >;
};

export const AlertSummaryFull = gql`
  fragment AlertSummaryFull on AlertSummary {
    alertId
    title
    severity
    type
    status
    creationTime
    deliveryResponses {
      ...DeliveryResponseFull
    }
    updateTime
    lastUpdatedBy
    lastUpdatedByTime
    detection {
      ... on AlertSummaryPolicyInfo {
        policyId
        resourceTypes
        resourceId
        policySourceId
      }
      ... on AlertSummaryRuleInfo {
        ruleId
        logTypes
        eventsMatched
      }
    }
  }
  ${DeliveryResponseFull}
`;
