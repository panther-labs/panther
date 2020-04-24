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
