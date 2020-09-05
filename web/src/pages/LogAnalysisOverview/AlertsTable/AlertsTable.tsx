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
import { Box, Link, Table, Icon } from 'pouncejs';
import urls from 'Source/urls';
import { Link as RRLink } from 'react-router-dom';
import SeverityBadge from 'Components/badges/SeverityBadge';
import { ListAlerts } from 'Pages/ListAlerts/graphql/listAlerts.generated';
import { shortenId, formatDatetime } from 'Helpers/utils';
import AlertStatusBadge from 'Components/badges/AlertStatusBadge';

type ListAlertsTableProps = {
  items: ListAlerts['alerts']['alertSummaries'];
};

const AlertsTableBody: React.FC<ListAlertsTableProps> = ({ items }) => {
  return (
    <Table>
      <Table.Head>
        <Table.Row>
          <Table.HeaderCell align="center">Severity</Table.HeaderCell>
          <Table.HeaderCell>Alert</Table.HeaderCell>
          <Table.HeaderCell />
          <Table.HeaderCell align="center">Status</Table.HeaderCell>
          <Table.HeaderCell align="right">Created At</Table.HeaderCell>
          <Table.HeaderCell align="right">Last Matched At</Table.HeaderCell>
          <Table.HeaderCell align="right">Events</Table.HeaderCell>
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {items.map(alert => (
          <Table.Row key={alert.alertId}>
            <Table.Cell align="center">
              <Box my={-1} display="inline-block">
                <SeverityBadge severity={alert.severity} />
              </Box>
            </Table.Cell>
            <Table.Cell maxWidth={300} truncated title={alert.title}>
              <Link
                as={RRLink}
                to={urls.logAnalysis.alerts.details(alert.alertId)}
                py={4}
                mr={4}
                truncated
              >
                #{shortenId(alert.alertId)} {alert.title}
              </Link>
            </Table.Cell>
            <Table.Cell wrapText="nowrap">
              <Box
                mx={-4}
                as="a"
                target="_blank"
                rel="noopener noreferrer"
                display="inline-flex"
                alignItems="center"
                href={`${window.location.origin}${urls.logAnalysis.rules.details(alert.ruleId)}`}
                fontSize="small"
                borderRadius="pill"
                transition="background-color 0.1s ease-in-out"
                // @ts-ignore
                backgroundColor="rgba(255,255,255,0.1)"
                _hover={{
                  // @ts-ignore
                  backgroundColor: 'rgba(255,255,255,0.15)',
                }}
                my={-1}
                py={1}
                px={4}
              >
                View Rule
                <Icon type="external-link" size="x-small" ml={1} />
              </Box>
            </Table.Cell>
            <Table.Cell align="center">
              <Box display="inline-block" my={-1}>
                <AlertStatusBadge
                  status={alert.status}
                  lastUpdatedBy={alert.lastUpdatedBy}
                  lastUpdatedByTime={alert.lastUpdatedByTime}
                />
              </Box>
            </Table.Cell>
            <Table.Cell align="right" wrapText="nowrap">
              {formatDatetime(alert.creationTime)}
            </Table.Cell>
            <Table.Cell align="right" wrapText="nowrap">
              {formatDatetime(alert.updateTime)}
            </Table.Cell>
            <Table.Cell align="right" mono>
              {alert.eventsMatched}
            </Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
};

export default React.memo(AlertsTableBody);
