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
import { Integration } from 'Generated/schema';
import { generateEnumerationColumn } from 'Helpers/utils';
import ListSourcesTableRowOptionsProps from 'Pages/list-sources/subcomponents/list-sources-table-row-options';

// The columns that the associated table will show
const columns = [
  generateEnumerationColumn(0),

  // The source label that user defined
  {
    key: 'integrationLabel',
    header: 'Label',
    flex: '1 0 200px',
  },

  {
    key: 'awsAccountId',
    header: 'AWS Account ID',
    flex: '1 0 200px',
  },

  {
    key: 's3Buckets',
    header: 'S3 Buckets',
    flex: '1 0 300px',
    renderCell: ({ s3Buckets }) => (
      <React.Fragment>
        {s3Buckets.map(s3Arn => (
          <Text size="medium" key={s3Arn} mb={1}>
            {s3Arn}
          </Text>
        ))}
      </React.Fragment>
    ),
  },

  {
    key: 'options',
    flex: '0 1 auto',
    renderColumnHeader: () => <Box mx={5} />,
    renderCell: item => <ListSourcesTableRowOptionsProps source={item} />,
  },
] as TableProps<Integration>['columns'];

export default columns;
