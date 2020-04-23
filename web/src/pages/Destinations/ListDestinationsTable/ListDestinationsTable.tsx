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
