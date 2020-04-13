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

/* eslint-disable import/order, import/no-duplicates, @typescript-eslint/no-unused-vars */

import * as Types from '../../../__generated__/schema';

import { RuleDetailsFragment } from './RuleDetailsFragment.generated';
import gql from 'graphql-tag';

export type RuleFragment = Pick<Types.RuleDetails, 'body'> & {
  tests?: Types.Maybe<
    Array<
      Types.Maybe<
        Pick<Types.PolicyUnitTest, 'expectedResult' | 'name' | 'resource' | 'resourceType'>
      >
    >
  >;
} & RuleDetailsFragment;

export const RuleFragment = gql`
  fragment RuleFragment on RuleDetails {
    ...RuleDetailsFragment
    body
    tests {
      expectedResult
      name
      resource
      resourceType
    }
  }
  ${RuleDetailsFragment}
`;
