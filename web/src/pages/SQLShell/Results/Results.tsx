import React from 'react';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';
import Panel from 'Components/Panel';
import { Box } from 'pouncejs';
import { LogQueryStatus } from 'Generated/schema';
import DownloadButton from 'Pages/SQLShell/Results/DownloadButton';
import { extractErrorMessage } from 'Helpers/utils';
import { useInfiniteScroll } from 'react-infinite-scroll-hook';
import { useGetLogQueryResults } from './graphql/getLogQueryResults.generated';
import { useSQLShellContext } from '../SQLShellContext';
import ResultsTable from './ResultsTable';

const POLL_INTERVAL_MS = 750;

const Results: React.FC = () => {
  const {
    state: { queryId },
    dispatch,
  } = useSQLShellContext();

  const {
    data,
    loading,
    error,
    startPolling,
    stopPolling,
    fetchMore,
    variables,
  } = useGetLogQueryResults({
    skip: !queryId,
    // FIXME: This is a temporary hack to fix an issue that exists with Apollo. When polling,
    // apollo won't update the "error" value. By setting `notifyOnNetworkStatusChange` to `true`,
    // we get more re-renders but at least the value gets updated correctly
    // https://github.com/apollographql/apollo-client/issues/5531
    notifyOnNetworkStatusChange: true,
    variables: {
      input: {
        queryId,
        pageSize: DEFAULT_LARGE_PAGE_SIZE,
      },
    },
  });

  // Hook to handle the fetching of more items when we scroll close to the end
  // TODO: implement through IntersectionObserver for better performance
  const infiniteRef = useInfiniteScroll({
    loading,
    hasNextPage: data?.getLogQuery?.pageInfo?.hasNextPage,
    checkInterval: 600,
    threshold: 500,
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

  // When we change a `queryId` by having a new query provisioned from the backend, then we
  // change the status to running (since the `useGetLogQueryResults` will have `skip: false` and
  // thus will begin querying for results
  React.useEffect(() => {
    if (queryId) {
      dispatch({ type: 'QUERY_RUNNING', payload: { queryId } });
    }
  }, [queryId]);

  // If the 1st round-trip for results gives us a status of "running", polling needs to start.
  const queryNeedsPolling = data?.getLogQuery.query.status === LogQueryStatus.Running;
  React.useEffect(() => {
    if (queryNeedsPolling) {
      startPolling(POLL_INTERVAL_MS);
    }
  }, [queryNeedsPolling]);

  // If a server round-trip gives us a status of "succeeded", polling needs to stop
  const isQuerySuccessful = data?.getLogQuery.query.status === LogQueryStatus.Succeeded;
  React.useEffect(() => {
    if (isQuerySuccessful) {
      stopPolling();
      dispatch({ type: 'QUERY_SUCCEEDED' });
    }
  }, [isQuerySuccessful]);

  // If a server round-trip gives us a status of "errored", polling needs to stop and we need to
  // let the user know what went wrong
  const hasQueryFailed = !!error || data?.getLogQuery?.query?.status === LogQueryStatus.Failed;
  React.useEffect(() => {
    if (hasQueryFailed) {
      stopPolling();
      dispatch({
        type: 'QUERY_ERRORED',
        payload: { message: error ? extractErrorMessage(error) : data?.getLogQuery.error?.message },
      });
    }
  }, [hasQueryFailed]);

  // If the query was canceled by the user, then we should stop polling immediately
  const queryWasCanceled = data?.getLogQuery?.query?.status === LogQueryStatus.Canceled;
  React.useEffect(() => {
    if (queryWasCanceled) {
      stopPolling();
    }
  }, [queryWasCanceled]);

  // Just because `Results` component renders a lot, we make sure to save un-necessary re-renders
  // on the download button side of things
  const downloadButton = React.useMemo(
    () => <DownloadButton isQuerySuccessful={isQuerySuccessful} />,
    [isQuerySuccessful]
  );

  return (
    <Panel title="Results" size="large" actions={downloadButton}>
      <Box innerRef={infiniteRef} height="100%">
        <ResultsTable isFetchingMore={loading} results={data?.getLogQuery?.results ?? []} />
      </Box>
    </Panel>
  );
};

export default Results;
