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

import React from 'react';
import { S3LogIntegration } from 'Generated/schema';
import { Flex, Table, Box } from 'pouncejs';

import LogSourceHealthIcon from 'Pages/ListLogSources/LogSourceTable/LogSourceHealthIcon';
import LogSourceTableRowOptionsProps from 'Pages/ListLogSources/LogSourceTable/LogSourceTableRowOptions/LogSourceTableRowOptions';
import s3Logo from 'Assets/s3-minimal-logo.svg';
import { formatDatetime } from 'Helpers/utils';
import LogSourceType from '../LogSourceType';

type LogSourceTypeProps = {
  source: S3LogIntegration;
};

const S3LogSourceRow: React.FC<LogSourceTypeProps> = ({ source }) => {
  return (
    <Table.Row key={source.integrationId}>
      <Table.Cell>{source.integrationLabel}</Table.Cell>
      <Table.Cell>
        <LogSourceType name="Amazon S3" logo={s3Logo} />
      </Table.Cell>
      <Table.Cell>{source.awsAccountId} </Table.Cell>
      <Table.Cell>{source.s3Bucket}</Table.Cell>
      <Table.Cell>
        {source.logTypes.map(logType => (
          <Box key={logType}>{logType}</Box>
        ))}
      </Table.Cell>
      <Table.Cell>
        {source.lastEventReceived ? formatDatetime(source.lastEventReceived) : 'N/A'}
      </Table.Cell>
      <Table.Cell>
        <Flex justify="center">
          {source.health ? <LogSourceHealthIcon logSourceHealth={source.health} /> : 'N/A'}
        </Flex>
      </Table.Cell>
      <Table.Cell>
        <Box my={-1}>
          <LogSourceTableRowOptionsProps source={source} />
        </Box>
      </Table.Cell>
    </Table.Row>
  );
};

export default React.memo(S3LogSourceRow);
