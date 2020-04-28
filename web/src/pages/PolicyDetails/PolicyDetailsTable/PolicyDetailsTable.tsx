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
import { ComplianceItem, ComplianceIntegration, ComplianceStatusEnum } from 'Generated/schema';
import { Box, Flex, Label, Link, Table, Tooltip } from 'pouncejs';
import urls from 'Source/urls';
import { capitalize, formatDatetime } from 'Helpers/utils';
import { Link as RRLink } from 'react-router-dom';
import RemediationButton from 'Components/buttons/RemediationButton/RemediationButton';
import SuppressButton from 'Components/buttons/SuppressButton/SuppressButton';

interface PolicyDetailsTableProps {
  items?: (ComplianceItem & Pick<ComplianceIntegration, 'integrationLabel'>)[];
  enumerationStartIndex: number;
}

const PolicyDetailsTable: React.FC<PolicyDetailsTableProps> = ({
  items,
  enumerationStartIndex,
}) => {
  return (
    <Table>
      <Table.Head>
        <Table.Row>
          <Table.HeaderCell />
          <Table.HeaderCell>Resource</Table.HeaderCell>
          <Table.HeaderCell>Status</Table.HeaderCell>
          <Table.HeaderCell>Source</Table.HeaderCell>
          <Table.HeaderCell>Last Updated</Table.HeaderCell>
          <Table.HeaderCell />
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {items.map((resource, index) => (
          <Table.Row key={resource.resourceId}>
            <Table.Cell>
              <Label size="medium">{enumerationStartIndex + index + 1}</Label>
            </Table.Cell>
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
            <Table.Cell
              color={resource.status === ComplianceStatusEnum.Pass ? 'green300' : 'red300'}
            >
              {resource.errorMessage ? (
                <Tooltip
                  positioning="down"
                  content={<Label size="medium">{resource.errorMessage}</Label>}
                >
                  {`${capitalize(resource.status.toLowerCase())} *`}
                </Tooltip>
              ) : (
                capitalize(resource.status.toLowerCase())
              )}
            </Table.Cell>
            <Table.Cell>{resource.integrationLabel}</Table.Cell>
            <Table.Cell>{formatDatetime(resource.lastUpdated)}</Table.Cell>
            <Table.Cell width={250}>
              <Flex my={-4} justify="flex-end">
                {resource.status !== ComplianceStatusEnum.Pass && (
                  <Box mr={4}>
                    <RemediationButton
                      buttonVariant="default"
                      policyId={resource.policyId}
                      resourceId={resource.resourceId}
                    />
                  </Box>
                )}
                {!resource.suppressed ? (
                  <SuppressButton
                    buttonVariant="default"
                    policyIds={[resource.policyId]}
                    resourcePatterns={[resource.resourceId]}
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

export default React.memo(PolicyDetailsTable);
