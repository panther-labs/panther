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
import { Text, TableProps, Box } from 'pouncejs';
import { ComplianceIntegration } from 'Generated/schema';
import { generateEnumerationColumn } from 'Helpers/utils';
import ComplianceSourceHealthIcon from './ComplianceSourceHealthIcon';
import ComplianceSourceTableRowOptions from './ComplianceSourceTableRowOptions';

// The columns that the associated table will show
const columns = [
  generateEnumerationColumn(0),

  // The source label that user defined
  {
    key: 'integrationLabel',
    header: 'Label',
    flex: '1 0 150px',
  },

  // The account is the `id` number of the aws account
  {
    key: 'awsAccountId',
    header: 'Account ID',
    flex: '1 0 125px',
  },

  {
    key: 'cweEnabled',
    header: 'Real-Time Updates',
    flex: '1 0 125px',
    renderCell: ({ cweEnabled }) => <Text size="large">{cweEnabled ? 'Enabled' : 'No'}</Text>,
  },

  {
    key: 'remediationEnabled',
    header: 'Auto-Remediations',
    flex: '1 0 125px',
    renderCell: ({ remediationEnabled }) => (
      <Text size="large">{remediationEnabled ? 'Automatic' : 'No'}</Text>
    ),
  },

  // Status displays the error message
  {
    key: 'health',
    header: 'Healthy',
    flex: '1 0 125px',
    renderCell: source => {
      return <ComplianceSourceHealthIcon complianceSourceHealth={source.health} />;
    },
  },
  {
    key: 'options',
    flex: '0 1 auto',
    renderColumnHeader: () => <Box mx={5} />,
    renderCell: item => <ComplianceSourceTableRowOptions source={item} />,
  },
] as TableProps<ComplianceIntegration>['columns'];

export default columns;
