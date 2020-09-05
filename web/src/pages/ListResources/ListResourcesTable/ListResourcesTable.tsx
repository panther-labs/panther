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
  ComplianceIntegration,
  ListResourcesInput,
  ListResourcesSortFieldsEnum,
  ResourceSummary,
  SortDirEnum,
} from 'Generated/schema';
import { formatDatetime } from 'Helpers/utils';
import { Box, Link, Table } from 'pouncejs';
import urls from 'Source/urls';
import { Link as RRLink } from 'react-router-dom';
import StatusBadge from 'Components/badges/StatusBadge';

interface ListResourcesTableProps {
  items?: Array<ResourceSummary & Pick<ComplianceIntegration, 'integrationLabel'>>;
  sortBy: ListResourcesSortFieldsEnum;
  sortDir: SortDirEnum;
  onSort: (params: Partial<ListResourcesInput>) => void;
}

const ListResourcesTable: React.FC<ListResourcesTableProps> = ({
  items,
  onSort,
  sortBy,
  sortDir,
}) => {
  const handleSort = (selectedKey: ListResourcesSortFieldsEnum) => {
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
            onClick={() => handleSort(ListResourcesSortFieldsEnum.Id)}
            sortDir={sortBy === ListResourcesSortFieldsEnum.Id ? sortDir : false}
          >
            Resource
          </Table.SortableHeaderCell>
          <Table.SortableHeaderCell
            onClick={() => handleSort(ListResourcesSortFieldsEnum.Type)}
            sortDir={sortBy === ListResourcesSortFieldsEnum.Type ? sortDir : false}
          >
            Type
          </Table.SortableHeaderCell>
          <Table.HeaderCell>Source</Table.HeaderCell>
          <Table.SortableHeaderCell
            align="center"
            onClick={() => handleSort(ListResourcesSortFieldsEnum.ComplianceStatus)}
            sortDir={sortBy === ListResourcesSortFieldsEnum.ComplianceStatus ? sortDir : false}
          >
            Status
          </Table.SortableHeaderCell>
          <Table.SortableHeaderCell
            onClick={() => handleSort(ListResourcesSortFieldsEnum.LastModified)}
            sortDir={sortBy === ListResourcesSortFieldsEnum.LastModified ? sortDir : false}
            align="right"
          >
            Last Modified
          </Table.SortableHeaderCell>
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {items.map(resource => (
          <Table.Row key={resource.id}>
            <Table.Cell maxWidth={450} wrapText="wrap">
              <Link as={RRLink} to={urls.compliance.resources.details(resource.id)} py={4} pr={4}>
                {resource.id}
              </Link>
            </Table.Cell>
            <Table.Cell>{resource.type}</Table.Cell>
            <Table.Cell>{resource.integrationLabel}</Table.Cell>
            <Table.Cell>
              <Box my={-1} display="inline-block">
                <StatusBadge status={resource.complianceStatus} />
              </Box>
            </Table.Cell>
            <Table.Cell align="right">{formatDatetime(resource.lastModified)}</Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
};

export default React.memo(ListResourcesTable);
