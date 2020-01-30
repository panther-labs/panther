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
import { GetAlertInput, AlertDetails, RuleDetails, GetRuleInput } from 'Generated/schema';
import { Alert, Box } from 'pouncejs';
import AlertDetailsInfo from 'Pages/alert-details/subcomponent/alert-details-info';
import AlertEvents from 'Pages/alert-details/subcomponent/alert-events';
import ErrorBoundary from 'Components/error-boundary';
import { extractErrorMessage } from 'Helpers/utils';
import AlertDetailsPageSkeleton from 'Pages/alert-details/skeleton';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';

export const ALERT_DETAILS = gql`
  query AlertDetails($input: GetAlertInput!) {
    alert(input: $input) {
      alertId
      ruleId
      creationTime
      eventsMatched
      lastEventMatched
      eventsLastEvaluatedKey
      events
    }
  }
`;

export const RULE_TEASER = gql`
  query RuleTeaser($input: GetRuleInput!) {
    rule(input: $input) {
      description
      displayName
      id
      logTypes
      runbook
      severity
      tags
    }
  }
`;

interface ApolloAlertQueryData {
  alert: AlertDetails;
}

interface ApolloAlertQueryInput {
  input: GetAlertInput;
}

interface ApolloRuleQueryData {
  rule: Partial<RuleDetails>;
}

interface ApolloRuleQueryInput {
  input: GetRuleInput;
}

const AlertDetailsPage = () => {
  const { match } = useRouter<{ id: string }>();

  const {
    data: alertData,
    loading: alertLoading,
    error: alertError,
    fetchMore,
    variables,
  } = useQuery<ApolloAlertQueryData, ApolloAlertQueryInput>(ALERT_DETAILS, {
    fetchPolicy: 'cache-and-network',
    variables: {
      input: {
        alertId: match.params.id,
        eventsPageSize: DEFAULT_LARGE_PAGE_SIZE,
      },
    },
  });

  const { data: ruleData, loading: ruleLoading } = useQuery<
    ApolloRuleQueryData,
    ApolloRuleQueryInput
  >(RULE_TEASER, {
    skip: !alertData,
    variables: {
      input: {
        ruleId: alertData?.alert.ruleId,
      },
    },
  });

  const fetchMoreEvents = React.useCallback(() => {
    fetchMore({
      variables: {
        input: {
          ...variables.input,
          eventsExclusiveStartKey: alertData.alert.eventsLastEvaluatedKey,
        },
      },
      updateQuery: (previousResult, { fetchMoreResult }) => {
        return {
          ...previousResult,
          ...fetchMoreResult,
          alert: {
            ...previousResult.alert,
            ...fetchMoreResult.alert,
            events: [...previousResult.alert.events, ...fetchMoreResult.alert.events],
          },
        };
      },
    });
  }, [fetchMore, variables, alertData]);

  if ((alertLoading && !alertData) || (ruleLoading && !ruleData)) {
    return <AlertDetailsPageSkeleton />;
  }

  if (alertError) {
    return (
      <Alert
        variant="error"
        title="Couldn't load alert"
        description={
          extractErrorMessage(alertError) ||
          "An unknown error occured and we couldn't load the alert details from the server"
        }
        mb={6}
      />
    );
  }

  return (
    <article>
      <Box mb={6}>
        <Box mb={4}>
          <ErrorBoundary>
            <AlertDetailsInfo alert={alertData.alert} rule={ruleData?.rule} />
          </ErrorBoundary>
        </Box>
        <ErrorBoundary>
          <AlertEvents
            events={alertData.alert.events}
            total={alertData.alert.eventsMatched}
            fetchMore={fetchMoreEvents}
          />
        </ErrorBoundary>
      </Box>
    </article>
  );
};

export default AlertDetailsPage;
