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
import { Table } from 'pouncejs';
import { ListLogSources } from 'Pages/ListLogSources';
import { S3LogIntegration, SqsLogSourceIntegration } from 'Generated/schema';
import { LogIntegrationsEnum } from 'Source/constants';
import S3LogSourceRow from './S3LogSourceRow';
import SqsLogSourceRow from './SqsLogSourceRow';

type LogSourceTableProps = {
  sources: ListLogSources['listLogIntegrations'];
};

const LogSourceTable: React.FC<LogSourceTableProps> = ({ sources }) => {
  return (
    <Table>
      <Table.Head>
        <Table.Row>
          <Table.HeaderCell>Label</Table.HeaderCell>
          <Table.HeaderCell align="center">Type</Table.HeaderCell>
          <Table.HeaderCell>AWS Account ID</Table.HeaderCell>
          <Table.HeaderCell>S3 Bucket</Table.HeaderCell>
          <Table.HeaderCell>Log Types</Table.HeaderCell>
          <Table.HeaderCell>Last Received Event</Table.HeaderCell>
          <Table.HeaderCell align="center">Healthy</Table.HeaderCell>
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {sources.map(source => {
          switch (source.integrationType) {
            case LogIntegrationsEnum.sqs: {
              return <SqsLogSourceRow source={source as SqsLogSourceIntegration} />;
            }
            case LogIntegrationsEnum.s3:
            default: {
              return <S3LogSourceRow source={source as S3LogIntegration} />;
            }
          }
        })}
      </Table.Body>
    </Table>
  );
};

export default React.memo(LogSourceTable);
