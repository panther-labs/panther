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
import { AbstractButton, Badge, Box, Icon, IconButton, Table, Tooltip } from 'pouncejs';
import { AlertDetails } from 'Pages/AlertDetails';
import { formatDatetime } from 'Helpers/utils';

// We expect an "enhanced" set of alert deliveriest that contains the delivery type & name
interface AlertDeliveryTableProps {
  alertDeliveries: AlertDetails['alert']['deliveryResponses'];
}

const AlertDeliveryTable: React.FC<AlertDeliveryTableProps> = ({ alertDeliveries }) => {
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
        {alertDeliveries.map(alertDelivery => (
          <Table.Row key={`${alertDelivery.outputId}${alertDelivery.dispatchedAt}`}>
            <Table.Cell>
              {/* FIXME: This actually needs to do something */}
              <AbstractButton
                backgroundColor="navyblue-300"
                borderRadius="circle"
                display="flex"
                p="2px"
                aria-label="Expand delivery information"
              >
                <Icon type="add" size="x-small" />
              </AbstractButton>
            </Table.Cell>
            <Table.Cell>{formatDatetime(alertDelivery.dispatchedAt)}</Table.Cell>
            {/* FIXME This needs to showcase logo + destination display name */}
            <Table.Cell>{alertDelivery.outputId}</Table.Cell>
            <Table.Cell align="center">
              <Box my={-1} display="inline-block">
                <Badge color={alertDelivery.success ? 'green-400' : 'red-200'}>
                  {alertDelivery.success ? 'SUCCESS' : 'FAIL'}
                </Badge>
              </Box>
            </Table.Cell>
            <Table.Cell align="center">{alertDelivery.statusCode}</Table.Cell>
            {/* FIXME This needs to actually be calculated in the FE based on `deliveryResponses` */}
            <Table.Cell align="center">TBD</Table.Cell>
            <Table.Cell align="right" maxWidth={150}>
              <Tooltip
                content={
                  <Box maxWidth={300} wordBreak="break-word">
                    {alertDelivery.message}
                  </Box>
                }
              >
                <Box truncated>{alertDelivery.message}</Box>
              </Tooltip>
            </Table.Cell>
            <Table.Cell>
              {!alertDelivery.success && (
                // FIXME: This needs to actually do something
                <Box my={-1}>
                  <IconButton
                    title="Retry delivery"
                    icon="refresh"
                    variant="ghost"
                    variantColor="navyblue"
                    size="small"
                    aria-label="Retry delivery"
                  />
                </Box>
              )}
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
};

export default AlertDeliveryTable;
