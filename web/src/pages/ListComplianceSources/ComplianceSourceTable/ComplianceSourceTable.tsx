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
