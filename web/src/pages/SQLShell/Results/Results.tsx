import React from 'react';
import useUrlParams from 'Hooks/useUrlParams';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';
import { Box } from 'pouncejs';
import { LogQueryStatus } from 'Generated/schema';
import { extractErrorMessage } from 'Helpers/utils';
import { useInfiniteScroll } from 'react-infinite-scroll-hook';
import { useGetLogQueryResults } from './graphql/getLogQueryResults.generated';
import { LogQueryUrlParams } from '../SQLEditor';
import { useSQLShellContext } from '../SQLShellContext';
import ResultsTable, { ResultsTableProps } from './ResultsTable';

const POLL_INTERVAL_MS = 750;

const Results: React.FC = () => {
  const { setGlobalErrorMessage } = useSQLShellContext();
  const { urlParams } = useUrlParams<LogQueryUrlParams>();
  const {
    data,
    loading,
    error,
    startPolling,
    stopPolling,
    fetchMore,
    variables,
  } = useGetLogQueryResults({
    skip: !urlParams.queryId,
    // FIXME: This is a temporary hack to fix an issue that exists with Apollo. When polling,
    // apollo won't update the "error" value. By setting `notifyOnNetworkStatusChange` to `true`,
    // we get more re-renders but at least the value gets updated correctly
    // https://github.com/apollographql/apollo-client/issues/5531
    notifyOnNetworkStatusChange: true,
    variables: {
      input: {
        queryId: urlParams.queryId,
        pageSize: DEFAULT_LARGE_PAGE_SIZE,
      },
    },
  });

  React.useEffect(() => {
    if (data && !error) {
      if (data.getLogQuery.query.status === LogQueryStatus.Running) {
        startPolling(POLL_INTERVAL_MS);
      } else {
        stopPolling();
      }
    }

    if (error) {
      stopPolling();
    }
  }, [data, error]);

  const infiniteRef = useInfiniteScroll({
    loading,
    hasNextPage: data?.getLogQuery?.pageInfo?.hasNextPage,
    checkInterval: 800, // The default is 200 which seems a bit too quick
    onLoadMore: () => {
      fetchMore({
        variables: {
          input: {
            ...variables.input,
            paginationToken: data.getLogQuery.pageInfo.paginationToken,
          },
        },
        updateQuery: (previousResult, { fetchMoreResult }) => {
          return {
            getLogQuery: {
              ...previousResult.getLogQuery,
              ...fetchMoreResult.getLogQuery,
              results: [
                ...previousResult.getLogQuery.results,
                ...fetchMoreResult.getLogQuery.results,
              ],
            },
          };
        },
      });
    },
  });

  const isQueryRunning = loading || data?.getLogQuery.query.status === LogQueryStatus.Running;
  const queryHasFailed = !!error || data?.getLogQuery?.query?.status === LogQueryStatus.Failed;

  React.useEffect(() => {
    if (queryHasFailed) {
      const errorMessage = error ? extractErrorMessage(error) : data?.getLogQuery.error?.message;
      setGlobalErrorMessage(errorMessage);
    }
  }, [queryHasFailed]);

  let tableState: ResultsTableProps['state'];
  if (!urlParams.queryId) {
    tableState = 'initial';
  }

  if (queryHasFailed) {
    tableState = 'hasErrored';
  }

  if (isQueryRunning) {
    tableState = 'isFetching';
  }

  return (
    <Box innerRef={infiniteRef}>
      <ResultsTable state={tableState} results={data?.getLogQuery?.results ?? []} />
    </Box>
  );
};

export default Results;
