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

/* eslint-disable react/display-name */

import React from 'react';
import { Badge, Box, TableProps, Text, Icon, Tooltip, Label } from 'pouncejs';
import { ComplianceStatusEnum, PolicySummary } from 'Generated/schema';
import { SEVERITY_COLOR_MAP } from 'Source/constants';
import { formatDatetime, capitalize } from 'Helpers/utils';
import ListPoliciesTableRowOptions from './ListPoliciesTableRowOptions';

// The columns that the associated table will show
const columns = [
  // Prefer to show the name. If it doesn't exist, fallback to the `id`
  {
    key: 'id',
    sortable: true,
    header: 'Policy',
    flex: '0 0 350px',
    renderCell: item => <Text size="medium">{item.displayName || item.id}</Text>,
  },

  // A resource type might not be specified, meaning that it applies to "All". Else render
  // one row for each resource type
  {
    key: 'resourceTypes',
    sortable: true,
    header: 'Resource Type',
    flex: '0 0 210px',
    renderCell: ({ resourceTypes }) =>
      resourceTypes.length ? (
        <div>
          {resourceTypes.map(resourceType => (
            <Text size="medium" wordBreak="break-word" key={resourceType} mb={1}>
              {resourceType}
            </Text>
          ))}
        </div>
      ) : (
        <Text size="medium">All resources</Text>
      ),
  },

  // Render badges to showcase severity
  {
    key: 'enabled',
    sortable: true,
    flex: '0 0 105px',
    header: 'Enabled',
    renderCell: ({ enabled }) => {
      return enabled ? (
        <Icon type="check" color="green300" size="small" />
      ) : (
        <Icon type="close" color="red300" size="small" />
      );
    },
  },

  // Render badges to showcase severity
  {
    key: 'severity',
    sortable: true,
    flex: '0 0 110px',
    header: 'Severity',
    renderCell: item => <Badge color={SEVERITY_COLOR_MAP[item.severity]}>{item.severity}</Badge>,
  },

  // Status of the policy. Changes color depending on fail|error or pass
  {
    key: 'complianceStatus',
    sortable: true,
    flex: '0 0 95px',
    header: 'Status',
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
                Policy raised an exception when evaluating a resource. Find out more in the policy
                {"'"}s page
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
    flex: '0 0 200px',
    renderCell: ({ lastModified }) => <Text size="medium">{formatDatetime(lastModified)}</Text>,
  },
  {
    key: 'options',
    flex: '0 1 auto',
    renderColumnHeader: () => <Box mx={5} />,
    renderCell: item => <ListPoliciesTableRowOptions policy={item} />,
  },
] as TableProps<PolicySummary>['columns'];

export default columns;
