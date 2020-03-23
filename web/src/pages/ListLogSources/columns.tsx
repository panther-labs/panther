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
import { TableProps, Box, Text } from 'pouncejs';
import { generateEnumerationColumn } from 'Helpers/utils';
import { LogIntegrationDetails } from 'Source/graphql/fragments/LogIntegrationDetails.generated';
import LogSourceTableRowOptions from './LogSourceTableRowOptions';
import LogSourceHealthIcon from './LogSourceHealthIcon';

// The columns that the associated table will show
const columns = [
  generateEnumerationColumn(0),

  // The source label that user defined
  {
    key: 'integrationLabel',
    header: 'Label',
    flex: '1 0 150px',
  },

  {
    key: 'awsAccountId',
    header: 'AWS Account ID',
    flex: '1 0 125px',
  },

  {
    key: 'logTypes',
    header: 'Log Types',
    flex: '1 0 125px',
    renderCell: ({ logTypes }) => (
      <Box>
        {logTypes.map(logType => (
          <Text size="medium" key={logType}>
            {logType}
          </Text>
        ))}
      </Box>
    ),
  },

  {
    key: 's3Bucket',
    header: 'S3 Bucket',
    flex: '1 0 200px',
  },

  {
    key: 's3Prefix',
    header: 'S3 Objects Prefix',
    flex: '1 0 100px',
    renderCell: ({ s3Prefix }) => <Text size="medium">{s3Prefix || 'None'}</Text>,
  },

  {
    key: 'health',
    header: 'Healthy',
    flex: '1 0 125px',
    renderCell: source => {
      return <LogSourceHealthIcon logSourceHealth={source.health} />;
    },
  },

  {
    key: 'options',
    flex: '0 1 auto',
    renderColumnHeader: () => <Box mx={5} />,
    renderCell: item => <LogSourceTableRowOptions source={item} />,
  },
] as TableProps<LogIntegrationDetails>['columns'];

export default columns;
