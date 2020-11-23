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
import { Card, Table, Text } from 'pouncejs';
import { DeliveryResponseFull } from 'Source/graphql/fragments/DeliveryResponseFull.generated';

interface DestinationTestErrorProps {
  response: DeliveryResponseFull;
}
const DestinationTestError: React.FC<DestinationTestErrorProps> = ({
  response: { outputId, dispatchedAt, success, statusCode, message },
}) => {
  return (
    <Card backgroundColor="pink-700" p={6}>
      <Table aria-label="Destination failure information" rowSeparationStrategy="none" size="small">
        <Table.Body>
          <Table.Row>
            <Table.Cell wrapText="nowrap" align="left">
              Dispatched at
            </Table.Cell>
            <Table.Cell align="left">
              <Text fontWeight="bold">{dispatchedAt}</Text>
            </Table.Cell>
          </Table.Row>
          <Table.Row>
            <Table.Cell align="left">Message</Table.Cell>
            <Table.Cell align="left">
              <Text fontWeight="bold">{message}</Text>
            </Table.Cell>
          </Table.Row>
          <Table.Row>
            <Table.Cell align="left">Output ID</Table.Cell>
            <Table.Cell align="left">
              <Text fontWeight="bold">{outputId}</Text>
            </Table.Cell>
          </Table.Row>
          <Table.Row>
            <Table.Cell align="left">Status Code</Table.Cell>
            <Table.Cell align="left">
              <Text fontWeight="bold">{statusCode}</Text>
            </Table.Cell>
          </Table.Row>
          <Table.Row>
            <Table.Cell align="left">Success</Table.Cell>
            <Table.Cell align="left">
              <Text fontWeight="bold">{success.toString()}</Text>
            </Table.Cell>
          </Table.Row>
        </Table.Body>
      </Table>
    </Card>
  );
};

export default React.memo(DestinationTestError);
