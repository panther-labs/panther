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
import { Flex, Table, Img, Box } from 'pouncejs';
import SeverityBadge from 'Components/SeverityBadge';
import { DESTINATIONS } from 'Source/constants';
import { formatDatetime } from 'Helpers/utils';
import { ListDestinationsAndDefaults } from 'Pages/Destinations';
import ListDestinationsTableRowOptionsProps from './ListDestinationsTableRowOptions';

type ListDestinationsTableProps = Pick<ListDestinationsAndDefaults, 'destinations'>;

const ListDestinationsTable: React.FC<ListDestinationsTableProps> = ({ destinations }) => {
  return (
    <Table>
      <Table.Head>
        <Table.Row>
          <Table.HeaderCell>Display Name</Table.HeaderCell>
          <Table.HeaderCell>Integrated Service</Table.HeaderCell>
          <Table.HeaderCell align="center">Associated Severities</Table.HeaderCell>
          <Table.HeaderCell>Created</Table.HeaderCell>
          <Table.HeaderCell />
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {destinations.map(destination => {
          const destinationConfig = DESTINATIONS[destination.outputType];

          return (
            <Table.Row key={destination.outputId}>
              <Table.Cell>{destination.displayName}</Table.Cell>
              <Table.Cell>
                <Flex align="center">
                  <Img
                    my={-4}
                    src={destinationConfig.logo}
                    alt={`${destinationConfig.title} Logo`}
                    nativeHeight={25}
                    nativeWidth={25}
                    mr={2}
                  />
                  <Box as="span">{destinationConfig.title}</Box>
                </Flex>
              </Table.Cell>
              <Table.Cell>
                <Flex spacing={2} my={-1} justify="center">
                  {destination.defaultForSeverity.map(severity => (
                    <SeverityBadge severity={severity} key={severity} />
                  ))}
                </Flex>
              </Table.Cell>
              <Table.Cell>{formatDatetime(destination.creationTime)}</Table.Cell>
              <Table.Cell>
                <Box my={-1}>
                  <ListDestinationsTableRowOptionsProps destination={destination} />
                </Box>
              </Table.Cell>
            </Table.Row>
          );
        })}
      </Table.Body>
    </Table>
  );
};

export default React.memo(ListDestinationsTable);
