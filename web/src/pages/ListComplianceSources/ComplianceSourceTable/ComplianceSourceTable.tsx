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
import { Flex, Label, Table } from 'pouncejs';
import { ListComplianceSources } from 'Pages/ListComplianceSources';
import ComplianceSourceHealthIcon from './ComplianceSourceHealthIcon';
import ComplianceSourceTableRowOptionsProps from './ComplianceSourceTableRowOptions';

type ComplianceSourceTableProps = {
  sources: ListComplianceSources['listComplianceIntegrations'];
};

const ComplianceSourceTable: React.FC<ComplianceSourceTableProps> = ({ sources }) => {
  return (
    <Table>
      <Table.Head>
        <Table.Row>
          <Table.HeaderCell />
          <Table.HeaderCell>Label</Table.HeaderCell>
          <Table.HeaderCell>AWS Account ID</Table.HeaderCell>
          <Table.HeaderCell>Real-Time Updates</Table.HeaderCell>
          <Table.HeaderCell>Auto-Remediations</Table.HeaderCell>
          <Table.HeaderCell align="center">Healthy</Table.HeaderCell>
          <Table.HeaderCell />
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {sources.map((source, index) => (
          <Table.Row key={source.integrationId}>
            <Table.Cell>
              <Label size="medium">{index + 1}</Label>
            </Table.Cell>
            <Table.Cell>{source.integrationLabel}</Table.Cell>
            <Table.Cell>{source.awsAccountId}</Table.Cell>
            <Table.Cell>{source.cweEnabled ? 'Enabled' : 'Disabled'}</Table.Cell>
            <Table.Cell>{source.remediationEnabled ? 'Enabled' : 'Disabled'}</Table.Cell>
            <Table.Cell>
              <Flex justify="center">
                <ComplianceSourceHealthIcon complianceSourceHealth={source.health} />
              </Flex>
            </Table.Cell>
            <Table.Cell>
              <ComplianceSourceTableRowOptionsProps source={source} />
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
};

export default React.memo(ComplianceSourceTable);
