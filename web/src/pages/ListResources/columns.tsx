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

/* eslint-disable react/display-name */

import React from 'react';
import { Text, TableProps, Tooltip, Label } from 'pouncejs';
import { ComplianceStatusEnum, ComplianceIntegration, ResourceSummary } from 'Generated/schema';
import { capitalize, formatDatetime } from 'Helpers/utils';

// The columns that the associated table will show
const columns = [
  // The name is the `id` of the resource
  {
    key: 'id',
    sortable: true,
    header: 'Resource',
    flex: '0 0 350px',
  },

  // The AWS type of this resouce (S3, IAM, etc.)
  {
    key: 'type',
    sortable: true,
    header: 'Type',
    flex: '0 1 275px',
  },

  // The AWS account associated with this resource within the context of an organization
  {
    key: 'integrationLabel',
    sortable: true,
    header: 'Source',
    flex: '1 0 100px',
  },

  // Status is not available yet. Mock it by alternative between hardcoded text
  {
    key: 'complianceStatus',
    sortable: true,
    header: 'Status',
    flex: '0 0 100px',
    renderCell: ({ complianceStatus }) => {
      const hasErrored = complianceStatus === ComplianceStatusEnum.Error;
      const textNode = (
        <Text
          size="medium"
          color={complianceStatus === ComplianceStatusEnum.Pass ? 'green300' : 'red300'}
        >
          {capitalize(complianceStatus.toLowerCase())}
          {hasErrored && ' *'}
        </Text>
      );

      if (hasErrored) {
        return (
          <Tooltip
            positioning="down"
            content={
              <Label size="medium">
                Some policies have raised an exception when evaluating this resource. Find out more
                in the resource{"'"}s page
              </Label>
            }
          >
            {textNode}
          </Tooltip>
        );
      }

      return textNode;
    },
  },

  // Date needs to be formatted properly
  {
    key: 'lastModified',
    sortable: true,
    header: 'Last Modified',
    flex: '0 1 225px',
    renderCell: ({ lastModified }) => <Text size="medium">{formatDatetime(lastModified)}</Text>,
  },
] as TableProps<ResourceSummary & Pick<ComplianceIntegration, 'integrationLabel'>>['columns'];

export default columns;
