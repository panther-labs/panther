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
import { Box, Link, Table } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import { formatDatetime, shortenId } from 'Helpers/utils';
import SeverityBadge from 'Components/badges/SeverityBadge';
import UpdateAlertDropdown from 'Components/dropdowns/UpdateAlertDropdown';
import { ListAlertsForRule } from '../graphql/listAlertsForRule.generated';

interface RuleDetailsAlertsTableProps {
  alerts: ListAlertsForRule['alerts']['alertSummaries'];
}

const RuleDetailsAlertsTable: React.FC<RuleDetailsAlertsTableProps> = ({ alerts }) => {
  return (
    <Table>
      <Table.Head>
        <Table.Row>
          <Table.HeaderCell align="center">Severity</Table.HeaderCell>
          <Table.HeaderCell>Alert</Table.HeaderCell>
          <Table.HeaderCell align="center">Status</Table.HeaderCell>
          <Table.HeaderCell align="right">Created At</Table.HeaderCell>
          <Table.HeaderCell align="right">Last Matched At</Table.HeaderCell>
          <Table.HeaderCell align="right">Events</Table.HeaderCell>
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {alerts.map(alert => (
          <Table.Row key={alert.alertId}>
            <Table.Cell align="center">
              <Box my={-1} display="inline-block">
                <SeverityBadge severity={alert.severity} />
              </Box>
            </Table.Cell>
            <Table.Cell maxWidth={400} truncated title={alert.title}>
              <Link as={RRLink} to={urls.logAnalysis.alerts.details(alert.alertId)} py={4} pr={4}>
                #{shortenId(alert.alertId)} {alert.title}
              </Link>
            </Table.Cell>
            <Table.Cell align="center">
              <UpdateAlertDropdown alert={alert} />
            </Table.Cell>
            <Table.Cell align="right">{formatDatetime(alert.creationTime)}</Table.Cell>
            <Table.Cell align="right">{formatDatetime(alert.updateTime)}</Table.Cell>
            <Table.Cell align="right" mono>
              {alert.eventsMatched}
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
};

export default RuleDetailsAlertsTable;
