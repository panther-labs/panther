/**
 * A Cloud-Native SIEM for the Modern Security Team
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
import { generateEnumerationColumn } from 'Helpers/utils';
import { Badge, TableProps } from 'pouncejs';
import { SEVERITY_COLOR_MAP } from 'Source/constants';
import { TopFailingPolicy, TopFailingResource } from 'Pages/ComplianceOverview/index';

/**
 * The columns that the top failing policies table will show
 */
export const topFailingPoliciesColumns = [
  // add an enumeration column starting from 0
  generateEnumerationColumn(0),

  // The name is the `id` of the policy
  {
    key: 'id',
    header: 'Policy',
    flex: '1 0 0',
  },

  // Render badges to showcase severity
  {
    key: 'severity',
    flex: '0 0 100px',
    header: 'Severity',
    renderCell: ({ severity }) => <Badge color={SEVERITY_COLOR_MAP[severity]}>{severity}</Badge>,
  },
] as TableProps<TopFailingPolicy>['columns'];

/**
 * The columns that the top failing resources table will show
 */
export const topFailingResourcesColumns = [
  // add an enumeration column starting from 0
  generateEnumerationColumn(0),

  // The name is the `id` of the policy
  {
    key: 'id',
    header: 'Resource',
    flex: '1 0 0',
  },
] as TableProps<TopFailingResource>['columns'];
