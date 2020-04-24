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
import { Label, SimpleGrid, Table } from 'pouncejs';
import SeverityBadge from 'Components/SeverityBadge';
import { formatDatetime } from 'Helpers/utils';
import { ListDestinationsAndDefaults } from 'Pages/Destinations';
import ListDestinationsTableRowOptionsProps from './ListDestinationsTableRowOptions';

type ListDestinationsTableProps = Pick<ListDestinationsAndDefaults, 'destinations'>;

const ListDestinationsTable: React.FC<ListDestinationsTableProps> = ({ destinations }) => {
  return (
    <Table>
      <Table.Head>
        <Table.Row>
          <Table.HeaderCell />
          <Table.HeaderCell>Display Name</Table.HeaderCell>
          <Table.HeaderCell>Integrated Service</Table.HeaderCell>
          <Table.HeaderCell>Associated Severities</Table.HeaderCell>
          <Table.HeaderCell>Created at</Table.HeaderCell>
          <Table.HeaderCell />
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {destinations.map((destination, index) => (
          <Table.Row key={destination.outputId}>
            <Table.Cell>
              <Label size="medium">{index + 1}</Label>
            </Table.Cell>
            <Table.Cell>{destination.displayName}</Table.Cell>
            <Table.Cell>{destination.outputType}</Table.Cell>
            <Table.Cell>
              <SimpleGrid
                inline
                spacingX={1}
                my={-1}
                columns={destination.defaultForSeverity.length}
              >
                {destination.defaultForSeverity.map(severity => (
                  <SeverityBadge severity={severity} key={severity} />
                ))}
              </SimpleGrid>
            </Table.Cell>
            <Table.Cell>{formatDatetime(destination.creationTime)}</Table.Cell>
            <Table.Cell>
              <ListDestinationsTableRowOptionsProps destination={destination} />
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
};

export default React.memo(ListDestinationsTable);
