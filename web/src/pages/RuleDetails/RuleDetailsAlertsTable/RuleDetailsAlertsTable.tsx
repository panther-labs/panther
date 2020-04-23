import React from 'react';
import { Label, Link, Table } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import { formatDatetime, shortenId } from 'Helpers/utils';
import { RuleDetails } from '../graphql/ruleDetails.generated';

interface RuleDetailsAlertsTableProps {
  alerts: RuleDetails['alerts']['alertSummaries'];
}

const RuleDetailsAlertsTable: React.FC<RuleDetailsAlertsTableProps> = ({ alerts }) => {
  return (
    <Table>
      <Table.Head>
        <Table.Row>
          <Table.HeaderCell />
          <Table.HeaderCell>Title</Table.HeaderCell>
          <Table.HeaderCell>Created At</Table.HeaderCell>
          <Table.HeaderCell>Alert ID</Table.HeaderCell>
          <Table.HeaderCell align="right">Events</Table.HeaderCell>
          <Table.HeaderCell>Last Matched At</Table.HeaderCell>
        </Table.Row>
      </Table.Head>
      <Table.Body>
        {alerts.map((alert, index) => (
          <Table.Row key={alert.alertId}>
            <Table.Cell>
              <Label size="medium">{index + 1}</Label>
            </Table.Cell>
            <Table.Cell maxWidth={450} truncated title={alert.title}>
              <Link as={RRLink} to={urls.logAnalysis.alerts.details(alert.alertId)} py={4} pr={4}>
                {alert.title}
              </Link>
            </Table.Cell>
            <Table.Cell>{formatDatetime(alert.creationTime)}</Table.Cell>
            <Table.Cell>{shortenId(alert.alertId)}</Table.Cell>
            <Table.Cell align="right">{alert.eventsMatched}</Table.Cell>
            <Table.Cell>{formatDatetime(alert.updateTime)}</Table.Cell>
          </Table.Row>
        ))}
      </Table.Body>
    </Table>
  );
};

export default RuleDetailsAlertsTable;
