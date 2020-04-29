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
import {
  ComplianceStatusEnum,
  ListPoliciesInput,
  ListPoliciesSortFieldsEnum,
  SortDirEnum,
} from 'Generated/schema';
import { capitalize, formatDatetime } from 'Helpers/utils';
import { Box, Flex, Icon, Label, Link, Table, Tooltip } from 'pouncejs';
import urls from 'Source/urls';
import { Link as RRLink } from 'react-router-dom';
import SeverityBadge from 'Components/SeverityBadge';
import { ListPolicies } from 'Pages/ListPolicies';
import ListPoliciesTableRowOptions from './ListPoliciesTableRowOptions';

interface ListPoliciesTableProps {
  items?: ListPolicies['policies']['policies'];
  sortBy: ListPoliciesSortFieldsEnum;
  sortDir: SortDirEnum;
  onSort: (params: Partial<ListPoliciesInput>) => void;
  enumerationStartIndex: number;
}

const ListPoliciesTable: React.FC<ListPoliciesTableProps> = ({
  items,
  onSort,
  sortBy,
  sortDir,
  enumerationStartIndex,
}) => {
  const handleSort = (selectedKey: ListPoliciesSortFieldsEnum) => {
    if (sortBy === selectedKey) {
      onSort({
        sortBy,
        sortDir: sortDir === SortDirEnum.Ascending ? SortDirEnum.Descending : SortDirEnum.Ascending,
      });
    } else {
      onSort({ sortBy: selectedKey, sortDir: SortDirEnum.Ascending });
    }
  };

  return (
    <Table>
      <Table.Head>
        <Table.Row>
          <Table.HeaderCell />
          <Table.SortableHeaderCell
            onClick={() => handleSort(ListPoliciesSortFieldsEnum.Id)}
            sortDir={sortBy === ListPoliciesSortFieldsEnum.Id ? sortDir : false}
          >
            Policy
          </Table.SortableHeaderCell>
          <Table.SortableHeaderCell
            onClick={() => handleSort(ListPoliciesSortFieldsEnum.ResourceTypes)}
            sortDir={sortBy === ListPoliciesSortFieldsEnum.ResourceTypes ? sortDir : false}
          >
            Resource Types
          </Table.SortableHeaderCell>
          <Table.SortableHeaderCell
            align="center"
            onClick={() => handleSort(ListPoliciesSortFieldsEnum.Enabled)}
            sortDir={sortBy === ListPoliciesSortFieldsEnum.Enabled ? sortDir : false}
          >
            Enabled
          </Table.SortableHeaderCell>
          <Table.SortableHeaderCell
            onClick={() => handleSort(ListPoliciesSortFieldsEnum.Severity)}
            sortDir={sortBy === ListPoliciesSortFieldsEnum.Severity ? sortDir : false}
          >
            Severity
          </Table.SortableHeaderCell>
          <Table.SortableHeaderCell
            align="center"
            onClick={() => handleSort(ListPoliciesSortFieldsEnum.ComplianceStatus)}
            sortDir={sortBy === ListPoliciesSortFieldsEnum.ComplianceStatus ? sortDir : false}
          >
            Status
          </Table.SortableHeaderCell>
          <Table.SortableHeaderCell
            onClick={() => handleSort(ListPoliciesSortFieldsEnum.LastModified)}
            sortDir={sortBy === ListPoliciesSortFieldsEnum.LastModified ? sortDir : false}
          >
            Last Modified
          </Table.SortableHeaderCell>
          <Table.HeaderCell />
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {items.map((policy, index) => (
          <Table.Row key={policy.id}>
            <Table.Cell>
              <Label size="medium">{enumerationStartIndex + index + 1}</Label>
            </Table.Cell>
            <Table.Cell maxWidth={450} wrapText="wrap">
              <Link as={RRLink} to={urls.compliance.policies.details(policy.id)} py={4} pr={4}>
                {policy.id}
              </Link>
            </Table.Cell>
            <Table.Cell maxWidth={225} truncated>
              {policy.resourceTypes.length
                ? policy.resourceTypes.map(resourceType => (
                    <React.Fragment key={resourceType}>
                      {resourceType} <br />
                    </React.Fragment>
                  ))
                : 'All resources'}
            </Table.Cell>
            <Table.Cell align="center">
              <Flex justify="center">
                {policy.enabled ? (
                  <Icon type="check" color="green300" size="small" />
                ) : (
                  <Icon type="close" color="red300" size="small" />
                )}
              </Flex>
            </Table.Cell>
            <Table.Cell>
              <Box my={-1}>
                <SeverityBadge severity={policy.severity} />
              </Box>
            </Table.Cell>
            <Table.Cell
              align="center"
              color={policy.complianceStatus === ComplianceStatusEnum.Pass ? 'green300' : 'red300'}
            >
              {policy.complianceStatus === ComplianceStatusEnum.Error ? (
                <Tooltip
                  positioning="down"
                  content={
                    <Label size="medium">
                      Policy raised an exception when evaluating a resource. Find out more in the
                      policy{"'"}s page
                    </Label>
                  }
                >
                  {`${capitalize(policy.complianceStatus.toLowerCase())} *`}
                </Tooltip>
              ) : (
                capitalize(policy.complianceStatus.toLowerCase())
              )}
            </Table.Cell>
            <Table.Cell>{formatDatetime(policy.lastModified)}</Table.Cell>
            <Table.Cell>
              <ListPoliciesTableRowOptions policy={policy} />
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
};

export default React.memo(ListPoliciesTable);
