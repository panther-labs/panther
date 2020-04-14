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
import { useInfiniteScroll } from 'react-infinite-scroll-hook';
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

  const infiniteRef = useInfiniteScroll<HTMLDivElement>({
    loading,
    hasNextPage: !!data?.alerts?.lastEvaluatedKey,
    checkInterval: 800, // The default is 200 which seems a bit too quick
    onLoadMore: () => {
      fetchMore({
        variables: {
          input: { pageSize: DEFAULT_LARGE_PAGE_SIZE, exclusiveStartKey: lastEvaluatedKey },
        },
        updateQuery: (previousResult, { fetchMoreResult }) => {
          return {
            alerts: {
              ...previousResult.alerts,
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
