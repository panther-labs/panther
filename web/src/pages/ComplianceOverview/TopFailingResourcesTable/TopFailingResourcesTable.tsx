import { Label, Link, Table } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import React from 'react';
import { GetOrganizationStats } from 'Pages/ComplianceOverview/graphql/getOrganizationStats.generated';

interface TopFailingResourcesTableProps {
  resources: GetOrganizationStats['organizationStats']['topFailingResources'];
}

const TopFailingResourcesTable: React.FC<TopFailingResourcesTableProps> = ({ resources }) => {
  return (
    <Table>
      <Table.Head>
        <Table.Row>
          <Table.HeaderCell />
          <Table.HeaderCell>Resource</Table.HeaderCell>
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {resources.map((resource, index) => (
          <Table.Row key={resource.id}>
            <Table.Cell>
              <Label size="medium">{index + 1}</Label>
            </Table.Cell>
            <Table.Cell>
              <Link as={RRLink} to={urls.compliance.resources.details(resource.id)} py={4} pr={4}>
                {resource.id}
              </Link>
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
};

export default TopFailingResourcesTable;
