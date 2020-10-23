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

import useRouter from 'Hooks/useRouter';
import { Alert, Box, Flex } from 'pouncejs';
import Panel from 'Components/Panel';
import { extractErrorMessage } from 'Helpers/utils';
import withSEO from 'Hoc/withSEO';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';
import useInfiniteScroll from 'Hooks/useInfiniteScroll';
import ErrorBoundary from 'Components/ErrorBoundary';
import TablePlaceholder from 'Components/TablePlaceholder';
import ListAlertsPageEmptyDataFallback from 'Pages/ListAlerts/EmptyDataFallback/EmptyDataFallback';
import AlertCard from 'Components/cards/AlertCard/AlertCard';
import RuleDetailsPageSkeleton from './Skeleton';
import RuleDetailsInfo from './RuleDetailsInfo';
import { useRuleDetails } from './graphql/ruleDetails.generated';
import { useListAlertsForRule } from './graphql/listAlertsForRule.generated';

const RuleDetailsPage = () => {
  const { match } = useRouter<{ id: string }>();
  const {
    error: ruleDetailsError,
    data: ruleDetailsData,
    loading: ruleDetailsLoading,
  } = useRuleDetails({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: {
        ruleId: match.params.id,
      },
    },
  });

  const {
    error: listAlertsError,
    data: listAlertsData,
    loading: listAlertsLoading,
    fetchMore,
    variables,
  } = useListAlertsForRule({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: {
        ruleId: match.params.id,
        pageSize: DEFAULT_LARGE_PAGE_SIZE,
      },
    },
  });

  const { sentinelRef } = useInfiniteScroll<HTMLDivElement>({
    loading: listAlertsLoading,
    threshold: 500,
    onLoadMore: () => {
      fetchMore({
        variables: {
          input: {
            ...variables.input,
            exclusiveStartKey: listAlertsData.alerts.lastEvaluatedKey,
          },
        },
        updateQuery: (previousResult, { fetchMoreResult }) => {
          // FIXME: Centralize this behavior for alert pagination, when apollo fixes a bug which
          // causes wrong params to be passed to the merge function in type policies
          // https://github.com/apollographql/apollo-client/issues/5951
          return {
            alerts: {
              ...fetchMoreResult.alerts,
              alertSummaries: [
                ...previousResult.alerts.alertSummaries,
                ...fetchMoreResult.alerts.alertSummaries,
              ],
            },
          };
        },
      });
    },
  });

  const loading = listAlertsLoading || ruleDetailsLoading;
  const data = !!listAlertsData && !!ruleDetailsData;
  const error = listAlertsError || ruleDetailsError;

  if (loading && !data) {
    return <RuleDetailsPageSkeleton />;
  }

  if (error) {
    return (
      <Box mb={6}>
        <Alert
          variant="error"
          title="Couldn't load rule"
          description={
            extractErrorMessage(error) ||
            " An unknown error occured and we couldn't load the rule details from the server"
          }
        />
      </Box>
    );
  }

  const hasAnyAlerts = listAlertsData?.alerts?.alertSummaries?.length > 0;
  const hasMoreAlerts = !!listAlertsData.alerts.lastEvaluatedKey;

  return (
    <article>
      <ErrorBoundary>
        <RuleDetailsInfo rule={ruleDetailsData.rule} />
      </ErrorBoundary>
      <Box mt={5} mb={6}>
        <Panel title="Alerts">
          <ErrorBoundary>
            {hasAnyAlerts && (
              <Flex direction="column" spacing={2}>
                {listAlertsData.alerts.alertSummaries.map(alert => (
                  <AlertCard key={alert.alertId} alert={alert} />
                ))}
              </Flex>
            )}
            {!hasAnyAlerts && <ListAlertsPageEmptyDataFallback />}
            {hasMoreAlerts && hasAnyAlerts && (
              <Box mt={8} ref={sentinelRef}>
                <TablePlaceholder rowCount={10} rowHeight={6} />
              </Box>
            )}
          </ErrorBoundary>
        </Panel>
      </Box>
    </article>
  );
};

export default withSEO({ title: ({ match }) => match.params.id })(RuleDetailsPage);
