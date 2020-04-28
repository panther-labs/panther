import React from 'react';
import Panel from 'Components/Panel';
import { LogQueryStatus } from 'Generated/schema';
import { extractErrorMessage } from 'Helpers/utils';
import { Box } from 'pouncejs';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';
import TablePlaceholder from 'Components/TablePlaceholder';
import useInfiniteScroll from 'Hooks/useInfiniteScroll';
import { useGetLogQueryResults } from './graphql/getLogQueryResults.generated';
import { useDataExplorerContext } from '../DataExplorerContext';
import DownloadButton from './DownloadButton';
import ResultsTable from './ResultsTable';

const POLL_INTERVAL_MS = 750;

const Results: React.FC = () => {
  const {
    state: { queryId },
    dispatch,
  } = useDataExplorerContext();

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
    // FIXME: `notifyOnNetworkStatusChange: true` is hack to fix an issue that exists with Apollo.
    // When polling, apollo won't update the "error" value. By setting this value to `true`,
    // we get more re-renders but at least the value gets updated correctly
    // https://github.com/apollographql/apollo-client/issues/5531

    // FIXME: We should add `fetchPolicy: 'no-cache'` since cache read/write take too long
    // Unfortunately, the "fetch more" doesn't currently work when specifying `no-cache` and thus
    // we are bound by slow read/writes when the results are "big". There is pending ticket to allow
    // to bypass cache, thus increasing performance
    // https://github.com/apollographql/apollo-client/issues/5239

    // FIXME: `data` contents are referentially  different after every `fetchMore` invocation
    // There is bug where when running fetchMore and `updateQuery`, all the items in a list get
    // different references. This forces React to re-render all the query results every time new
    // paginated items get fetched from the server
    // https://github.com/apollographql/apollo-client/issues/6202
    notifyOnNetworkStatusChange: true,
    variables: {
      input: {
        queryId,
        pageSize: DEFAULT_LARGE_PAGE_SIZE,
      },
    },
  });

  // Hook to handle the fetching of more items when we scroll close to the end
  const { sentinelRef } = useInfiniteScroll<HTMLElement>({
    loading,
    scrollContainer: 'parent',
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
  React.useLayoutEffect(() => {
    if (queryId) {
      dispatch({ type: 'QUERY_RUNNING', payload: { queryId } });
    }
  }, [queryId]);

  // If the 1st round-trip for results gives us a status of "running", polling needs to start.
  const queryNeedsPolling = data?.getLogQuery?.query?.status === LogQueryStatus.Running;
  React.useEffect(() => {
    if (queryNeedsPolling) {
      startPolling(POLL_INTERVAL_MS);
    }
  }, [queryNeedsPolling]);

  // If a server round-trip gives us a status of "succeeded", polling needs to stop
  const isQuerySuccessful = data?.getLogQuery?.query?.status === LogQueryStatus.Succeeded;
  React.useLayoutEffect(() => {
    if (isQuerySuccessful) {
      dispatch({ type: 'QUERY_SUCCEEDED' });
      stopPolling();
    }
  }, [isQuerySuccessful]);

  // If a server round-trip gives us a status of "errored", polling needs to stop and we need to
  // let the user know what went wrong
  const hasQueryFailed = !!error || data?.getLogQuery?.query?.status === LogQueryStatus.Failed;
  React.useEffect(() => {
    if (hasQueryFailed) {
      dispatch({
        type: 'QUERY_ERRORED',
        payload: { message: error ? extractErrorMessage(error) : data?.getLogQuery.error?.message },
      });
      stopPolling();
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

  const results = data?.getLogQuery?.results ?? [];
  const hasNextPage = data?.getLogQuery?.pageInfo?.hasNextPage;
  return (
    <Panel title="Results" size="large" actions={downloadButton}>
      <Box overflow="scroll" minHeight={400} maxHeight="calc(100vh - 900px)" willChange="scroll">
        <ResultsTable results={results} />
        {hasNextPage && (
          <Box mt={4} ref={sentinelRef}>
            <TablePlaceholder rowCount={10} rowHeight={6} />
          </Box>
        )}
      </Box>
    </Panel>
  );
};

export default Results;
