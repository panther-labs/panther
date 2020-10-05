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
import { ComplianceItem, ComplianceIntegration } from 'Generated/schema';
import { Box, Link, Table } from 'pouncejs';
import urls from 'Source/urls';
import { formatDatetime } from 'Helpers/utils';
import { Link as RRLink } from 'react-router-dom';
import StatusBadge from 'Components/badges/StatusBadge';
import PolicyDetailsTableRowOptions from './PolicyDetailsTableRowOptions';

export type PolicyDetailsTableItem = ComplianceItem &
  Pick<ComplianceIntegration, 'integrationLabel'>;

export interface PolicyDetailsTableProps {
  items?: PolicyDetailsTableItem[];
}

const PolicyDetailsTable: React.FC<PolicyDetailsTableProps> = ({ items }) => {
  return (
    <Table>
      <Table.Head>
        <Table.Row>
          <Table.HeaderCell>Resource</Table.HeaderCell>
          <Table.HeaderCell>Source</Table.HeaderCell>
          <Table.HeaderCell align="center">Status</Table.HeaderCell>
          <Table.HeaderCell align="right">Last Modified</Table.HeaderCell>
          <Table.HeaderCell />
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {items.map(resource => (
          <Table.Row key={resource.resourceId}>
            <Table.Cell maxWidth={450} truncated title={resource.resourceId}>
              <Link
                as={RRLink}
                to={urls.compliance.resources.details(resource.resourceId)}
                py={4}
                pr={4}
              >
                {resource.resourceId}
              </Link>
            </Table.Cell>
            <Table.Cell>{resource.integrationLabel}</Table.Cell>
            <Table.Cell align="center">
              <Box my={-1} display="inline-block">
                <StatusBadge
                  status={resource.status}
                  disabled={resource.suppressed}
                  errorMessage={resource.errorMessage}
                  disabledLabel="IGNORED"
                />
              </Box>
            </Table.Cell>
            <Table.Cell align="right">{formatDatetime(resource.lastUpdated)}</Table.Cell>
            <Table.Cell align="right">
              <Box my={-2}>
                <PolicyDetailsTableRowOptions complianceItem={resource} />
              </Box>
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
};

export default React.memo(PolicyDetailsTable);
