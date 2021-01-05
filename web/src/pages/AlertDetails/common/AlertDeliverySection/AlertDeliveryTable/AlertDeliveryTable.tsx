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
import { AbstractButton, Badge, Box, Flex, Icon, IconButton, Img, Table, Tooltip } from 'pouncejs';
import { Destination } from 'Generated/schema';
import { AlertDetails } from 'Pages/AlertDetails';
import { formatDatetime } from 'Helpers/utils';
import groupBy from 'lodash/groupBy';
import { DESTINATIONS } from 'Source/constants';

// We expect an "enhanced" set of alert deliveriest that contains the delivery type & name
interface AlertDeliveryTableProps {
  alertDeliveries: (AlertDetails['alert']['deliveryResponses'][0] &
    Pick<Destination, 'displayName' | 'outputType'>)[];
  onAlertDeliveryRetry: (outputId: string) => void;
  isResending: boolean;
}

const AlertDeliveryTable: React.FC<AlertDeliveryTableProps> = ({
  alertDeliveries,
  onAlertDeliveryRetry,
  isResending,
}) => {
  const [expandedDestination, setExpandedDestination] = React.useState<string>(null);

  const alertDeliveriesByDestination = React.useMemo(() => {
    const destinationsByOutputId = groupBy(alertDeliveries, d => d.outputId);
    return Object.values(destinationsByOutputId);
  }, [alertDeliveries]);

  return (
    <Table data-testid="alert-delivery-table">
      <Table.Head>
        <Table.Row>
          <Table.HeaderCell />
          <Table.HeaderCell>Last Timestamp</Table.HeaderCell>
          <Table.HeaderCell>Destination</Table.HeaderCell>
          <Table.HeaderCell align="center">Status</Table.HeaderCell>
          <Table.HeaderCell align="center">HTTP Status Code</Table.HeaderCell>
          <Table.HeaderCell align="center">Retries</Table.HeaderCell>
          <Table.HeaderCell align="right">Message</Table.HeaderCell>
          <Table.HeaderCell />
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {alertDeliveriesByDestination.map(destinationDeliveries => {
          const [mostRecentDelivery, ...restDeliveries] = destinationDeliveries;
          return (
            <React.Fragment
              key={`${mostRecentDelivery.outputId}${mostRecentDelivery.dispatchedAt}`}
            >
              <Table.Row>
                <Table.Cell>
                  {!!restDeliveries.length && (
                    <AbstractButton
                      backgroundColor="navyblue-300"
                      borderRadius="circle"
                      display="flex"
                      p="2px"
                      aria-label="Expand delivery information"
                      onClick={() =>
                        setExpandedDestination(
                          expandedDestination === mostRecentDelivery.outputId
                            ? null
                            : mostRecentDelivery.outputId
                        )
                      }
                    >
                      <Icon
                        size="x-small"
                        type={
                          expandedDestination === mostRecentDelivery.outputId ? 'subtract' : 'add'
                        }
                      />
                    </AbstractButton>
                  )}
                </Table.Cell>
                <Table.Cell>{formatDatetime(mostRecentDelivery.dispatchedAt)}</Table.Cell>
                <Table.Cell>
                  <Flex align="center">
                    <Img
                      alt={`${mostRecentDelivery.outputType} logo`}
                      src={DESTINATIONS[mostRecentDelivery.outputType]?.logo}
                      nativeWidth={18}
                      nativeHeight={18}
                      mr={2}
                    />
                    {mostRecentDelivery.displayName}
                  </Flex>
                </Table.Cell>
                <Table.Cell align="center">
                  <Box my={-1} display="inline-block">
                    <Badge color={mostRecentDelivery.success ? 'green-400' : 'red-200'}>
                      {mostRecentDelivery.success ? 'SUCCESS' : 'FAIL'}
                    </Badge>
                  </Box>
                </Table.Cell>
                <Table.Cell align="center">{mostRecentDelivery.statusCode}</Table.Cell>
                <Table.Cell align="center">{destinationDeliveries.length}</Table.Cell>
                <Table.Cell align="right" maxWidth={150}>
                  <Tooltip
                    content={
                      <Box maxWidth={300} wordBreak="break-word">
                        {mostRecentDelivery.message}
                      </Box>
                    }
                  >
                    <Box truncated>{mostRecentDelivery.message}</Box>
                  </Tooltip>
                </Table.Cell>
                <Table.Cell>
                  {!mostRecentDelivery.success && (
                    <Box my={-2}>
                      <IconButton
                        title="Retry delivery"
                        icon="refresh"
                        disabled={isResending}
                        variant="ghost"
                        variantBorderStyle="circle"
                        variantColor="navyblue"
                        size="medium"
                        aria-label="Retry delivery"
                        onClick={() => onAlertDeliveryRetry(mostRecentDelivery.outputId)}
                      />
                    </Box>
                  )}
                </Table.Cell>
              </Table.Row>
              {expandedDestination === mostRecentDelivery.outputId &&
                restDeliveries.map(destinationDelivery => (
                  <Table.Row
                    selected
                    key={`${destinationDelivery.outputId}${destinationDelivery.dispatchedAt}`}
                  >
                    <Table.Cell />
                    <Table.Cell>{formatDatetime(destinationDelivery.dispatchedAt)}</Table.Cell>
                    <Table.Cell />
                    <Table.Cell align="center">
                      <Box as="b" color={destinationDelivery.success ? 'green-400' : 'red-200'}>
                        {destinationDelivery.success ? 'SUCCESS' : 'FAIL'}
                      </Box>
                    </Table.Cell>
                    <Table.Cell align="center">{destinationDelivery.statusCode}</Table.Cell>
                    <Table.Cell align="center" />
                    <Table.Cell align="right" maxWidth={150}>
                      <Tooltip
                        content={
                          <Box maxWidth={300} wordBreak="break-word">
                            {destinationDelivery.message}
                          </Box>
                        }
                      >
                        <Box truncated>{destinationDelivery.message}</Box>
                      </Tooltip>
                    </Table.Cell>
                    <Table.Cell />
                  </Table.Row>
                ))}
            </React.Fragment>
          );
        })}
      </Table.Body>
    </Table>
  );
};

export default AlertDeliveryTable;
