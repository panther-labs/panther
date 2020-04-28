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
import { ComplianceStatusEnum } from 'Generated/schema';
import { Box, Flex, Label, Link, Table, Tooltip } from 'pouncejs';
import urls from 'Source/urls';
import { capitalize } from 'Helpers/utils';
import { Link as RRLink } from 'react-router-dom';
import SeverityBadge from 'Components/SeverityBadge';
import { ResourceDetails } from 'Pages/ResourceDetails';
import RemediationButton from 'Components/buttons/RemediationButton/RemediationButton';
import SuppressButton from 'Components/buttons/SuppressButton/SuppressButton';

interface ResourcesDetailsTableProps {
  policies?: ResourceDetails['policiesForResource']['items'];
  enumerationStartIndex: number;
}

const ResourcesDetailsTable: React.FC<ResourcesDetailsTableProps> = ({
  enumerationStartIndex,
  policies,
}) => {
  return (
    <Table>
      <Table.Head>
        <Table.Row>
          <Table.HeaderCell />
          <Table.HeaderCell>Policy</Table.HeaderCell>
          <Table.HeaderCell>Status</Table.HeaderCell>
          <Table.HeaderCell>Severity</Table.HeaderCell>
          <Table.HeaderCell />
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {policies.map((policy, index) => (
          <Table.Row key={policy.policyId}>
            <Table.Cell>
              <Label size="medium">{enumerationStartIndex + index + 1}</Label>
            </Table.Cell>
            <Table.Cell maxWidth={450} truncated title={policy.policyId}>
              <Link
                as={RRLink}
                to={urls.compliance.policies.details(policy.policyId)}
                py={4}
                pr={4}
              >
                {policy.policyId}
              </Link>
            </Table.Cell>
            <Table.Cell color={policy.status === ComplianceStatusEnum.Pass ? 'green300' : 'red300'}>
              {policy.errorMessage ? (
                <Tooltip
                  positioning="down"
                  content={<Label size="medium">{policy.errorMessage}</Label>}
                >
                  {`${capitalize(policy.status.toLowerCase())} *`}
                </Tooltip>
              ) : (
                capitalize(policy.status.toLowerCase())
              )}
            </Table.Cell>
            <Table.Cell>
              <Box m={-1}>
                <SeverityBadge severity={policy.policySeverity} />
              </Box>
            </Table.Cell>
            <Table.Cell width={250}>
              <Flex my={-4} justify="flex-end">
                {policy.status !== ComplianceStatusEnum.Pass && (
                  <Box mr={4}>
                    <RemediationButton
                      buttonVariant="default"
                      policyId={policy.policyId}
                      resourceId={policy.resourceId}
                    />
                  </Box>
                )}
                {!policy.suppressed ? (
                  <SuppressButton
                    buttonVariant="default"
                    policyIds={[policy.policyId]}
                    resourcePatterns={[policy.resourceId]}
                  />
                ) : (
                  <Label color="orange300" size="medium">
                    IGNORED
                  </Label>
                )}
              </Flex>
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
};

export default React.memo(ResourcesDetailsTable);
