/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

import useRouter from 'Hooks/useRouter';
import { useQuery, gql } from '@apollo/client';
import {
  AlertSummary,
  GetRuleInput,
  ListAlertsInput,
  ListAlertsResponse,
  RuleDetails,
} from 'Generated/schema';
import { Alert, Box, Table } from 'pouncejs';
import RuleDetailsInfo from 'Pages/rule-details/subcomponents/rule-details-info';
import Panel from 'Components/panel';
import urls from 'Source/urls';
import { extractErrorMessage } from 'Helpers/utils';
import ErrorBoundary from 'Components/error-boundary';
import columns from './columns';
import RuleDetailsPageSkeleton from './skeleton';

export const RULE_DETAILS = gql`
  query RuleDetails($ruleDetailsInput: GetRuleInput!, $alertsForRuleInput: ListAlertsInput!) {
    rule(input: $ruleDetailsInput) {
      createdAt
      description
      displayName
      enabled
      id
      lastModified
      reference
      logTypes
      runbook
      severity
      tags
    }
    alerts(input: $alertsForRuleInput) {
      alertSummaries {
        alertId
        creationTime
      }
    }
  }
`;

interface ApolloQueryData {
  rule: RuleDetails;
  alerts: ListAlertsResponse;
}

interface ApolloQueryInput {
  ruleDetailsInput: GetRuleInput;
  alertsForRuleInput: ListAlertsInput;
}

const RuleDetailsPage = () => {
  const { match } = useRouter<{ id: string }>();
  const { history } = useRouter();
  const { error, data, loading } = useQuery<ApolloQueryData, ApolloQueryInput>(RULE_DETAILS, {
    fetchPolicy: 'cache-and-network',
    variables: {
      ruleDetailsInput: {
        ruleId: match.params.id,
      },
      alertsForRuleInput: {
        ruleId: match.params.id,
      },
    },
  });

  if (loading && !data) {
    return <RuleDetailsPageSkeleton />;
  }

  if (error) {
    return (
      <Alert
        variant="error"
        title="Couldn't load rule"
        description={
          extractErrorMessage(error) ||
          " An unknown error occured and we couldn't load the rule details from the server"
        }
        mb={6}
      />
    );
  }

  return (
    <article>
      <ErrorBoundary>
        <RuleDetailsInfo rule={data.rule} />
      </ErrorBoundary>
      <Box mt={2} mb={6}>
        <Panel size="large" title="Alerts">
          <ErrorBoundary>
            <Table<AlertSummary>
              columns={columns}
              getItemKey={alert => alert.alertId}
              items={data.alerts.alertSummaries}
              onSelect={alert => history.push(urls.alerts.details(alert.alertId))}
            />
          </ErrorBoundary>
        </Panel>
      </Box>
    </article>
  );
};

export default RuleDetailsPage;
