import React from 'react';
import useUrlParams from 'Hooks/useUrlParams';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';
import { LogQueryStatus } from 'Generated/schema';
import { Box, Flex, Heading, Icon, Table } from 'pouncejs';
import BlankCanvasImg from 'Assets/illustrations/blank-canvas.svg';
import WarningImg from 'Assets/illustrations/warning.svg';
import TablePlaceholder from 'Components/TablePlaceholder';
import { extractErrorMessage } from 'Helpers/utils';
import { useGetLogQueryResults } from './graphql/getLogQueryResults.generated';
import { LogQueryUrlParams } from '../SQLEditor';
import { useSQLShellContext } from '../SQLShellContext';

const POLL_INTERVAL_MS = 750;

const ResultsTable: React.FC = () => {
  const { setGlobalErrorMessage } = useSQLShellContext();
  const { urlParams } = useUrlParams<LogQueryUrlParams>();
  const { data, loading, error, startPolling, stopPolling } = useGetLogQueryResults({
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

  const queryHasFailed = !!error || data?.getLogQuery?.query?.status === LogQueryStatus.Failed;
  React.useEffect(() => {
    if (queryHasFailed) {
      const errorMessage = error ? extractErrorMessage(error) : data?.getLogQuery.error?.message;
      setGlobalErrorMessage(errorMessage);
    }
  }, [queryHasFailed]);

  if (!urlParams.queryId) {
    return (
      <Flex
        justifyContent="center"
        alignItems="center"
        flexDirection="column"
        color="grey200"
        my={100}
      >
        <Icon size="large" type="search" />
        <Heading size="medium" my={6}>
          Write a query to see results
        </Heading>
      </Flex>
    );
  }

  if (queryHasFailed) {
    return (
      <Flex justifyContent="center" alignItems="center" flexDirection="column">
        <Box my={10}>
          <img alt="Road works Illustration" src={WarningImg} width="auto" height={200} />
        </Box>
        <Heading size="medium" color="grey200" mb={6}>
          Your query has errors. Look up.
        </Heading>
      </Flex>
    );
  }

  const isQueryRunning = loading || data?.getLogQuery.query.status === LogQueryStatus.Running;
  if (isQueryRunning) {
    return <TablePlaceholder />;
  }

  const { results } = data.getLogQuery;
  if (!results.length) {
    return (
      <Flex justifyContent="center" alignItems="center" flexDirection="column">
        <Box my={10}>
          <img alt="Black Canvas Illustration" src={BlankCanvasImg} width="auto" height={150} />
        </Box>
        <Heading size="medium" color="grey200" mb={6}>
          No results were found for your query
        </Heading>
      </Flex>
    );
  }

  return (
    <Box overflowX="scroll">
      <Table items={results} columns={[]} />
    </Box>
  );
};

export default ResultsTable;
