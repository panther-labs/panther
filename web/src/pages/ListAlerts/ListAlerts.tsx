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
import { Alert, Box, Card, Spinner } from 'pouncejs';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';
import { extractErrorMessage } from 'Helpers/utils';
import useInfiniteScroll from 'Hooks/useInfiniteScroll';
import ErrorBoundary from 'Components/ErrorBoundary';
import { useListAlerts } from './graphql/listAlerts.generated';
import ListAlertsTable from './ListAlertsTable';
import ListAlertsPageSkeleton from './Skeleton';
import ListAlertsPageEmptyDataFallback from './EmptyDataFallback';

const ListAlerts = () => {
  const { loading, error, data, fetchMore } = useListAlerts({
    notifyOnNetworkStatusChange: true, // Adding notifyOnNetworkStatusChange will enable 'loading' to update its status during fetchMore requests as well
    fetchPolicy: 'cache-and-network',
    variables: {
      input: {
        pageSize: DEFAULT_LARGE_PAGE_SIZE,
      },
    },
  });

  const alertItems = data?.alerts.alertSummaries || [];
  const lastEvaluatedKey = data?.alerts.lastEvaluatedKey || null;
  const { infiniteRef, setHasNextPage } = useInfiniteScroll({
    loading,
    // eslint-disable-next-line @typescript-eslint/no-use-before-define
    onLoadMore: () => {
      // Even though we're setting hasNextPage as false when exclusiveStartKey is null
      // the react-infinite-scroll-hook library still makes one last request before finally stopping
      // We're adding this redundant check explicitly just to be sure
      if (!lastEvaluatedKey) {
        return;
      }

      fetchMore({
        variables: {
          input: { pageSize: DEFAULT_LARGE_PAGE_SIZE, exclusiveStartKey: lastEvaluatedKey },
        },
        updateQuery: (previousResult, { fetchMoreResult }) => {
          if (!fetchMoreResult) {
            return previousResult;
          }
          const newAlertSummaries = fetchMoreResult.alerts.alertSummaries;
          const newLastEvaluatedKey = fetchMoreResult.alerts.lastEvaluatedKey;
          if (!newLastEvaluatedKey) {
            setHasNextPage(false); // newLastEvaluatedKey being null means there are no more items to query
          }
          return {
            alerts: {
              ...previousResult.alerts,
              alertSummaries: [...previousResult.alerts.alertSummaries, ...newAlertSummaries],
              lastEvaluatedKey: newLastEvaluatedKey,
            },
          };
        },
      });
    },
  });

  if (loading && !data) {
    return <ListAlertsPageSkeleton />;
  }

  if (error) {
    return (
      <Alert
        mb={6}
        variant="error"
        title="Couldn't load your alerts"
        description={
          extractErrorMessage(error) ||
          'There was an error when performing your request, please contact support@runpanther.io'
        }
      />
    );
  }

  if (!alertItems.length) {
    return <ListAlertsPageEmptyDataFallback />;
  }

  //  Check how many active filters exist by checking how many columns keys exist in the URL
  return (
    <ErrorBoundary>
      <div ref={infiniteRef}>
        <Card mb={8}>
          <ListAlertsTable items={alertItems} />
        </Card>
        {loading && (
          <Box mb={8}>
            <Spinner size="large" margin="auto" />
          </Box>
        )}
      </div>
    </ErrorBoundary>
  );
};

export default ListAlerts;
