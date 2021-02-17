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

import { AnalysisPackSummary } from './AnalysisPackSummary.generated';
import { GlobalPythonModuleFull } from './GlobalPythonModuleFull.generated';
import { DataModelFull } from './DataModelFull.generated';
import { RuleSummary } from './RuleSummary.generated';
import { PolicySummary } from './PolicySummary.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';

export type AnalysisPackDetails = {
  enumeration: {
    paging: Pick<Types.PagingData, 'thisPage' | 'totalPages' | 'totalItems'>;
    globals: Array<GlobalPythonModuleFull>;
    models: Array<DataModelFull>;
    detections: Array<PolicySummary | RuleSummary>;
  };
} & AnalysisPackSummary;

export const AnalysisPackDetails = gql`
  fragment AnalysisPackDetails on AnalysisPack {
    ...AnalysisPackSummary
    enumeration {
      paging {
        thisPage
        totalPages
        totalItems
      }
      globals {
        ...GlobalPythonModuleFull
      }
      models {
        ...DataModelFull
      }
      detections {
        ... on Rule {
          ...RuleSummary
        }
        ... on Policy {
          ...PolicySummary
        }
      }
    }
  }
  ${AnalysisPackSummary}
  ${GlobalPythonModuleFull}
  ${DataModelFull}
  ${RuleSummary}
  ${PolicySummary}
`;
