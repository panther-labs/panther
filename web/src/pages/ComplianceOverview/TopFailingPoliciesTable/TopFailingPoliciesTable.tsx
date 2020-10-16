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

import { Box, Link, Table } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import SeverityBadge from 'Components/badges/SeverityBadge';
import React from 'react';
import { GetOrganizationStats } from 'Pages/ComplianceOverview/graphql/getOrganizationStats.generated';

interface TopFailingPoliciesTableProps {
  policies: GetOrganizationStats['organizationStats']['topFailingPolicies'];
}

const TopFailingPoliciesTable: React.FC<TopFailingPoliciesTableProps> = ({ policies }) => {
  return (
    <Table>
      <Table.Head>
        <Table.Row>
          <Table.HeaderCell />
          <Table.HeaderCell>Policy</Table.HeaderCell>
          <Table.HeaderCell align="center">Severity</Table.HeaderCell>
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {policies.map((policy, index) => (
          <Table.Row key={policy.id}>
            <Table.Cell>{index + 1}</Table.Cell>
            <Table.Cell>
              <Link
                as={RRLink}
                to={urls.compliance.policies.details(policy.id)}
                py={4}
                pr={4}
                wordBreak="break-all"
              >
                {policy.id}
              </Link>
            </Table.Cell>
            <Table.Cell align="center">
              <Box my={-1} display="inline-block">
                <SeverityBadge severity={policy.severity} />
              </Box>
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
};

export default TopFailingPoliciesTable;
