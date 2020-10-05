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
import { Box, Link, Table } from 'pouncejs';
import urls from 'Source/urls';
import { Link as RRLink } from 'react-router-dom';
import SeverityBadge from 'Components/badges/SeverityBadge';
import StatusBadge from 'Components/badges/StatusBadge';
import { ResourceDetails } from '../graphql/resourceDetails.generated';
import ResourceDetailsTableRowOptions from './ResourceDetailsTableRowOptions';

export type ResourceDetailsTableItem = ResourceDetails['policiesForResource']['items'][0];

interface ResourcesDetailsTableProps {
  policies?: ResourceDetailsTableItem[];
}

const ResourcesDetailsTable: React.FC<ResourcesDetailsTableProps> = ({ policies }) => {
  return (
    <Table>
      <Table.Head>
        <Table.Row>
          <Table.HeaderCell>Policy</Table.HeaderCell>
          <Table.HeaderCell align="center">Status</Table.HeaderCell>
          <Table.HeaderCell align="center">Severity</Table.HeaderCell>
          <Table.HeaderCell />
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {policies.map(policy => (
          <Table.Row key={policy.policyId}>
            <Table.Cell truncated title={policy.policyId}>
              <Link
                as={RRLink}
                to={urls.compliance.policies.details(policy.policyId)}
                py={4}
                pr={4}
              >
                {policy.policyId}
              </Link>
            </Table.Cell>
            <Table.Cell align="center">
              <Box my={-1} display="inline-block">
                <StatusBadge
                  status={policy.status}
                  disabled={policy.suppressed}
                  errorMessage={policy.errorMessage}
                  disabledLabel="IGNORED"
                />
              </Box>
            </Table.Cell>
            <Table.Cell align="center">
              <Box my={-1} display="inline-block">
                <SeverityBadge severity={policy.policySeverity} />
              </Box>
            </Table.Cell>
            <Table.Cell align="right">
              <Box my={-2}>
                <ResourceDetailsTableRowOptions complianceItem={policy} />
              </Box>
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
};

export default React.memo(ResourcesDetailsTable);
