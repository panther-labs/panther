import React from 'react';
import { Box, Label, Table } from 'pouncejs';
import { ListLogSources } from 'Pages/ListLogSources';
import LogSourceHealthIcon from './LogSourceHealthIcon';
import LogSourceTableRowOptionsProps from './LogSourceTableRowOptions';

type LogSourceTableProps = {
  sources: ListLogSources['listLogIntegrations'];
};

const LogSourceTable: React.FC<LogSourceTableProps> = ({ sources }) => {
  return (
    <Table>
      <Table.Head>
        <Table.Row>
          <Table.HeaderCell />
          <Table.HeaderCell>Label</Table.HeaderCell>
          <Table.HeaderCell>AWS Account ID</Table.HeaderCell>
          <Table.HeaderCell>Log Types</Table.HeaderCell>
          <Table.HeaderCell>S3 Bucket</Table.HeaderCell>
          <Table.HeaderCell>S3 Objects Prefix</Table.HeaderCell>
          <Table.HeaderCell>Healthy</Table.HeaderCell>
          <Table.HeaderCell />
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {sources.map((source, index) => (
          <Table.Row key={source.integrationId}>
            <Table.Cell>
              <Label size="medium">{index + 1}</Label>
            </Table.Cell>
            <Table.Cell>{source.integrationLabel}</Table.Cell>
            <Table.Cell>{source.awsAccountId}</Table.Cell>
            <Table.Cell>
              {source.logTypes.map(logType => (
                <Box key={logType}>{logType}</Box>
              ))}
            </Table.Cell>
            <Table.Cell>{source.s3Bucket}</Table.Cell>
            <Table.Cell>{source.s3Prefix || 'None'}</Table.Cell>
            <Table.Cell>
              <LogSourceHealthIcon logSourceHealth={source.health} />
            </Table.Cell>
            <Table.Cell>
              <LogSourceTableRowOptionsProps source={source} />
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
};

export default React.memo(LogSourceTable);
