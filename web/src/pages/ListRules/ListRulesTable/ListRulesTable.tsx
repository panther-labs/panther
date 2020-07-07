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
import { ListRulesInput, ListRulesSortFieldsEnum, SortDirEnum } from 'Generated/schema';
import { formatDatetime } from 'Helpers/utils';
import { Box, Link, Table } from 'pouncejs';
import StatusBadge from 'Components/StatusBadge';
import urls from 'Source/urls';
import { Link as RRLink } from 'react-router-dom';
import SeverityBadge from 'Components/SeverityBadge';
import { ListRules } from 'Pages/ListRules';
import ListRulesTableRowOptions from './ListRulesTableRowOptions';

interface ListRulesTableProps {
  items?: ListRules['rules']['rules'];
  sortBy: ListRulesSortFieldsEnum;
  sortDir: SortDirEnum;
  onSort: (params: Partial<ListRulesInput>) => void;
}

const ListRulesTable: React.FC<ListRulesTableProps> = ({ items, onSort, sortBy, sortDir }) => {
  const handleSort = (selectedKey: ListRulesSortFieldsEnum) => {
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
            onClick={() => handleSort(ListRulesSortFieldsEnum.Id)}
            sortDir={sortBy === ListRulesSortFieldsEnum.Id ? sortDir : false}
          >
            Rule
          </Table.SortableHeaderCell>
          <Table.SortableHeaderCell
            onClick={() => handleSort(ListRulesSortFieldsEnum.LogTypes)}
            sortDir={sortBy === ListRulesSortFieldsEnum.LogTypes ? sortDir : false}
          >
            Log Types
          </Table.SortableHeaderCell>
          <Table.SortableHeaderCell
            align="center"
            onClick={() => handleSort(ListRulesSortFieldsEnum.Enabled)}
            sortDir={sortBy === ListRulesSortFieldsEnum.Enabled ? sortDir : false}
          >
            Status
          </Table.SortableHeaderCell>
          <Table.SortableHeaderCell
            onClick={() => handleSort(ListRulesSortFieldsEnum.Severity)}
            sortDir={sortBy === ListRulesSortFieldsEnum.Severity ? sortDir : false}
            align="center"
          >
            Severity
          </Table.SortableHeaderCell>
          <Table.SortableHeaderCell
            onClick={() => handleSort(ListRulesSortFieldsEnum.LastModified)}
            sortDir={sortBy === ListRulesSortFieldsEnum.LastModified ? sortDir : false}
            align="right"
          >
            Last Modified
          </Table.SortableHeaderCell>
          <Table.HeaderCell />
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {items.map(rule => (
          <Table.Row key={rule.id}>
            <Table.Cell maxWidth={450} wrapText="wrap">
              <Link as={RRLink} to={urls.logAnalysis.rules.details(rule.id)} py={4} pr={4}>
                {rule.displayName || rule.id}
              </Link>
            </Table.Cell>
            <Table.Cell maxWidth={225} truncated>
              {rule.logTypes.length
                ? rule.logTypes.map(logType => (
                    <React.Fragment key={logType}>
                      {logType} <br />
                    </React.Fragment>
                  ))
                : 'All resources'}
            </Table.Cell>
            <Table.Cell align="center">
              <Box my={-1} display="inline-block">
                <StatusBadge status="ENABLED" disabled={!rule.enabled} />
              </Box>
            </Table.Cell>
            <Table.Cell align="center">
              <Box my={-1} display="inline-block">
                <SeverityBadge severity={rule.severity} />
              </Box>
            </Table.Cell>
            <Table.Cell align="right">{formatDatetime(rule.lastModified)}</Table.Cell>
            <Table.Cell>
              <Box my={-1}>
                <ListRulesTableRowOptions rule={rule} />
              </Box>
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
};

export default React.memo(ListRulesTable);
