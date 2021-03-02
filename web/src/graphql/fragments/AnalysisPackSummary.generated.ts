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

import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';

export type AnalysisPackSummary = Pick<
  Types.AnalysisPack,
  | 'id'
  | 'displayName'
  | 'description'
  | 'enabled'
  | 'updateAvailable'
  | 'lastModified'
  | 'lastModifiedBy'
  | 'createdAt'
  | 'createdBy'
> & {
  packVersion: Pick<Types.AnalysisPackVersion, 'id' | 'semVer'>;
  availableVersions: Array<Pick<Types.AnalysisPackVersion, 'id' | 'semVer'>>;
  packTypes: Pick<Types.AnalysisPackTypes, 'GLOBAL' | 'POLICY' | 'RULE' | 'DATAMODEL'>;
  packDefinition: Pick<Types.AnalysisPackDefinition, 'IDs'>;
};

export const AnalysisPackSummary = gql`
  fragment AnalysisPackSummary on AnalysisPack {
    id
    displayName
    description
    enabled
    updateAvailable
    packVersion {
      id
      semVer
    }
    availableVersions {
      id
      semVer
    }
    packTypes {
      GLOBAL
      POLICY
      RULE
      DATAMODEL
    }
    packDefinition {
      IDs
    }
    lastModified
    lastModifiedBy
    createdAt
    createdBy
  }
`;
