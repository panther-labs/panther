import React from 'react';
import { Dropdown, Icon, IconButton, Label, MenuItem, SimpleGrid, Table } from 'pouncejs';
import SeverityBadge from 'Components/SeverityBadge';
import { formatDatetime } from 'Helpers/utils';
import useModal from 'Hooks/useModal';
import useSidesheet from 'Hooks/useSidesheet';
import { SIDESHEETS } from 'Components/utils/Sidesheet';
import { MODALS } from 'Components/utils/Modal';
import { ListDestinationsAndDefaults } from '../graphql/listDestinationsAndDefaults.generated';

type ListDestinationsTableProps = Pick<ListDestinationsAndDefaults, 'destinations'>;

const ListDestinationsTable: React.FC<ListDestinationsTableProps> = ({ destinations }) => {
  const { showModal } = useModal();
  const { showSidesheet } = useSidesheet();

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
              <Dropdown
                trigger={
                  <IconButton as="div" variant="default" my={-4}>
                    <Icon type="more" size="small" />
                  </IconButton>
                }
              >
                <Dropdown.Item
                  onSelect={() =>
                    showSidesheet({
                      sidesheet: SIDESHEETS.UPDATE_DESTINATION,
                      props: { destination },
                    })
                  }
                >
                  <MenuItem variant="default">Edit</MenuItem>
                </Dropdown.Item>
                <Dropdown.Item
                  onSelect={() =>
                    showModal({
                      modal: MODALS.DELETE_DESTINATION,
                      props: { destination },
                    })
                  }
                >
                  <MenuItem variant="default">Delete</MenuItem>
                </Dropdown.Item>
              </Dropdown>
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
};

export default React.memo(ListDestinationsTable);
