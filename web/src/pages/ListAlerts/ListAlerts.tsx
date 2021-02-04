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
import { Alert, Box, Card, Flex, Text } from 'pouncejs';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';
import { extractErrorMessage } from 'Helpers/utils';
import { ListAlertsInput } from 'Generated/schema';
import useInfiniteScroll from 'Hooks/useInfiniteScroll';
import useRequestParamsWithoutPagination from 'Hooks/useRequestParamsWithoutPagination';
import TablePlaceholder from 'Components/TablePlaceholder';
import NoResultsFound from 'Components/NoResultsFound';
import ErrorBoundary from 'Components/ErrorBoundary';
import isEmpty from 'lodash/isEmpty';
import withSEO from 'Hoc/withSEO';
import useTrackPageView from 'Hooks/useTrackPageView';
import { PageViewEnum } from 'Helpers/analytics';
import AlertCard from 'Components/cards/AlertCard';
import { SelectAllCheckbox, withSelectContext } from 'Components/utils/SelectContext';
import { compose } from 'Helpers/compose';
import ListAlertsActions from 'Pages/ListAlerts/ListAlertsActions';
import Panel from 'Components/Panel';
import { useListAlerts } from './graphql/listAlerts.generated';
import ListAlertBreadcrumbFilters from './ListAlertBreadcrumbFilters';
import ListAlertsPageSkeleton from './Skeleton';
import ListAlertsPageEmptyDataFallback from './EmptyDataFallback';

const ListAlerts = () => {
  useTrackPageView(PageViewEnum.ListAlerts);
  const { requestParams } = useRequestParamsWithoutPagination<ListAlertsInput>();
  const { loading, error, data, fetchMore } = useListAlerts({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: {
        ...requestParams,
        pageSize: DEFAULT_LARGE_PAGE_SIZE,
      },
    },
  });

  const alertItems = data?.alerts.alertSummaries || [];
  const lastEvaluatedKey = data?.alerts.lastEvaluatedKey || null;
  const hasNextPage = !!data?.alerts?.lastEvaluatedKey;

  const alertIds = React.useMemo(() => alertItems.map(a => a.alertId), [alertItems.length]);

  const { sentinelRef } = useInfiniteScroll<HTMLDivElement>({
    loading,
    threshold: 500,
    onLoadMore: () => {
      fetchMore({
        variables: {
          input: {
            ...requestParams,
            pageSize: DEFAULT_LARGE_PAGE_SIZE,
            exclusiveStartKey: lastEvaluatedKey,
          },
        },
        updateQuery: (previousResult, { fetchMoreResult }) => {
          // FIXME: Centralize this behavior for alert pagination, when apollo fixes a bug which
          // causes wrong params to be passed to the merge function in type policies
          // https://github.com/apollographql/apollo-client/issues/5951

          // PreviousResults now contains cached data and could have the same records (alertIds)
          // as the incoming results. Therefore, we must merge them and not just concatenate.

          // Create a set of old alertIds
          const oldAlertIds = new Set(
            previousResult.alerts.alertSummaries.map(({ alertId }) => alertId)
          );

          // Create a new merged array. Don't update old cached values because it isn't necessary (yet).
          const mergedAlertSummaries = [
            ...previousResult.alerts.alertSummaries,
            ...fetchMoreResult.alerts.alertSummaries.filter(
              ({ alertId }) => !oldAlertIds.has(alertId)
            ),
          ];

          return {
            alerts: {
              ...fetchMoreResult.alerts,
              alertSummaries: mergedAlertSummaries,
            },
          };
        },
      });
    },
  });

  if (loading && !data) {
    return <ListAlertsPageSkeleton />;
  }

  if (!alertItems.length && isEmpty(requestParams)) {
    return <ListAlertsPageEmptyDataFallback />;
  }

  const hasError = Boolean(error);
  return (
    <ErrorBoundary>
      {hasError && (
        <Box mb={6}>
          <Alert
            variant="error"
            title="Couldn't load your alerts"
            description={
              extractErrorMessage(error) ||
              'There was an error when performing your request, please contact support@runpanther.io'
            }
          />
        </Box>
      )}
      <ListAlertBreadcrumbFilters />
      <Panel
        title={
          <Flex align="center" spacing={2} ml={4}>
            <SelectAllCheckbox selectionItems={alertIds} />
            <Text>Alerts</Text>
          </Flex>
        }
        actions={<ListAlertsActions />}
      >
        <Card as="section" position="relative">
          <Box position="relative">
            <Flex direction="column" spacing={2}>
              {alertItems.length ? (
                alertItems.map(alert => (
                  <AlertCard key={alert.alertId} alert={alert} selectionEnabled />
                ))
              ) : (
                <Box my={8}>
                  <NoResultsFound />
                </Box>
              )}
            </Flex>
            {hasNextPage && (
              <Box py={8} ref={sentinelRef}>
                <TablePlaceholder rowCount={10} />
              </Box>
            )}
          </Box>
        </Card>
      </Panel>
    </ErrorBoundary>
  );
};

export default compose(withSEO({ title: 'Alerts' }), withSelectContext, React.memo)(ListAlerts);
