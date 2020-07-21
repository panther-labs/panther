/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import { SqsLogSourceIntegration } from 'Generated/schema';
import { Flex, Table, Box } from 'pouncejs';
import LogSourceType from 'Pages/ListLogSources/LogSourceTable/LogSourceType/LogSourceType';
import LogSourceHealthIcon from 'Pages/ListLogSources/LogSourceTable/LogSourceHealthIcon';
import LogSourceTableRowOptionsProps from 'Pages/ListLogSources/LogSourceTable/LogSourceTableRowOptions/LogSourceTableRowOptions';
import sqsLogo from 'Assets/sqs-minimal-logo.svg';
import { formatDatetime } from 'Helpers/utils';

type LogSourceTypeProps = {
  source: SqsLogSourceIntegration;
};

const SqsLogSourceRow: React.FC<LogSourceTypeProps> = ({ source }) => {
  return (
    <Table.Row key={source.integrationId}>
      <Table.Cell>{source.integrationLabel}</Table.Cell>
      <Table.Cell>
        <LogSourceType name="Amazon SQS" logo={sqsLogo} />
      </Table.Cell>
      <Table.Cell>N/A</Table.Cell>
      <Table.Cell>{source.sqsConfig.s3Bucket}</Table.Cell>
      <Table.Cell>
        {source.sqsConfig.logTypes.map(logType => (
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

export default React.memo(SqsLogSourceRow);
