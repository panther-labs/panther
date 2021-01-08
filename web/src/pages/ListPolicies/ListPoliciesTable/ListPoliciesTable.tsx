/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
import { ListPoliciesInput, ListPoliciesSortFieldsEnum, SortDirEnum } from 'Generated/schema';
import { formatDatetime } from 'Helpers/utils';
import { Box, Link, Table } from 'pouncejs';
import urls from 'Source/urls';
import { Link as RRLink } from 'react-router-dom';
import SeverityBadge from 'Components/badges/SeverityBadge';
import { ListPolicies } from 'Pages/ListPolicies';
import StatusBadge from 'Components/badges/StatusBadge';
import ListPoliciesTableRowOptions from './ListPoliciesTableRowOptions';

interface ListPoliciesTableProps {
  items?: ListPolicies['policies']['policies'];
  sortBy: ListPoliciesSortFieldsEnum;
  sortDir: SortDirEnum;
  onSort: (params: Partial<ListPoliciesInput>) => void;
}

const ListPoliciesTable: React.FC<ListPoliciesTableProps> = ({
  items,
  onSort,
  sortBy,
  sortDir,
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
            align="right"
          >
            Last Modified
          </Table.SortableHeaderCell>
          <Table.HeaderCell />
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {items.map(policy => (
          <Table.Row key={policy.id}>
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
            <Table.Cell>
              <Box my={-1} display="inline-block">
                <SeverityBadge severity={policy.severity} />
              </Box>
            </Table.Cell>
            <Table.Cell align="center">
              <Box my={-1} display="inline-block">
                <StatusBadge status={policy.complianceStatus} disabled={!policy.enabled} />
              </Box>
            </Table.Cell>
            <Table.Cell wrapText="nowrap" align="right">
              {formatDatetime(policy.lastModified)}
            </Table.Cell>
            <Table.Cell align="right">
              <Box my={-2}>
                <ListPoliciesTableRowOptions policy={policy} />
              </Box>
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
};

export default React.memo(ListPoliciesTable);
