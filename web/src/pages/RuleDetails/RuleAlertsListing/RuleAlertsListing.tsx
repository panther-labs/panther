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
import { Flex, Box, Card, Alert } from 'pouncejs';
import useRequestParamsWithoutPagination from 'Hooks/useRequestParamsWithoutPagination';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';
import { ListAlertsInput } from 'Generated/schema';
import ErrorBoundary from 'Components/ErrorBoundary';
import { extractErrorMessage } from 'Helpers/utils';
import ListAlertsPageEmptyDataFallback from 'Pages/ListAlerts/EmptyDataFallback/EmptyDataFallback';
import AlertCard from 'Components/cards/AlertCard/AlertCard';
import TablePlaceholder from 'Components/TablePlaceholder';
import useInfiniteScroll from 'Hooks/useInfiniteScroll';
import ListAlertFilters from 'Pages/ListAlerts/ListAlertFilters';
import { useListAlertsForRule } from '../graphql/listAlertsForRule.generated';
import Skeleton from './Skeleton';
import { RuleDetailsPageUrlParams } from '../RuleDetails';

const RuleAlertsListing: React.FC<Required<Pick<ListAlertsInput, 'type' | 'ruleId'>>> = ({
  ruleId,
  type,
}) => {
  const { requestParams } = useRequestParamsWithoutPagination<
    Omit<ListAlertsInput, 'ruleId' | 'type'> & RuleDetailsPageUrlParams
  >();

  // Omit the actual tab section as it exists on the url params
  const { section, ...params } = requestParams;

  const { error, data, loading, fetchMore, variables } = useListAlertsForRule({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: {
        ...params,
        type,
        ruleId,
        pageSize: DEFAULT_LARGE_PAGE_SIZE,
      },
    },
  });

  const { sentinelRef } = useInfiniteScroll<HTMLDivElement>({
    loading,
    threshold: 500,
    onLoadMore: () => {
      fetchMore({
        variables: {
          input: {
            ...variables.input,
            exclusiveStartKey: data.alerts.lastEvaluatedKey,
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

  if (loading && !data) {
    return <Skeleton />;
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

  const hasAnyAlerts = data?.alerts?.alertSummaries?.length > 0;
  const hasMoreAlerts = !!data?.alerts.lastEvaluatedKey;

  return (
    <ErrorBoundary>
      <Flex width="100%" pt={6} px={6}>
        <ListAlertFilters />
      </Flex>
      <Card as="article" p={6}>
        {hasAnyAlerts && (
          <Flex direction="column" spacing={2}>
            {data.alerts.alertSummaries.map(alert => (
              <AlertCard hideRuleLink={true} key={alert.alertId} alert={alert} />
            ))}
          </Flex>
        )}
        {!hasAnyAlerts && <ListAlertsPageEmptyDataFallback />}
        {hasMoreAlerts && hasAnyAlerts && (
          <Box mt={8} ref={sentinelRef}>
            <TablePlaceholder rowCount={10} rowHeight={6} />
          </Box>
        )}
      </Card>
    </ErrorBoundary>
  );
};

export default RuleAlertsListing;
