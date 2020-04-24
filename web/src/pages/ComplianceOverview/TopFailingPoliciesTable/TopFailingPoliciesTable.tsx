import { Box, Label, Link, Table } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import SeverityBadge from 'Components/SeverityBadge';
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
          <Table.HeaderCell>Severity</Table.HeaderCell>
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {policies.map((policy, index) => (
          <Table.Row key={policy.id}>
            <Table.Cell>
              <Label size="medium">{index + 1}</Label>
            </Table.Cell>
            <Table.Cell>
              <Link as={RRLink} to={urls.compliance.policies.details(policy.id)} py={4} pr={4}>
                {policy.id}
              </Link>
            </Table.Cell>
            <Table.Cell>
              <Box m={-1}>
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
