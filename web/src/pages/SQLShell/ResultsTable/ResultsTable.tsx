import React from 'react';
import useUrlParams from 'Hooks/useUrlParams';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';
import { LogQueryStatus } from 'Generated/schema';
import { Box, Flex, Heading, Icon, Table, Text } from 'pouncejs';
import BlankCanvasImg from 'Assets/illustrations/blank-canvas.svg';
import TablePlaceholder from 'Components/TablePlaceholder';
import { extractErrorMessage } from 'Helpers/utils';
import { useGetLogQueryResults } from './graphql/getLogQueryResults.generated';
import { LogQueryUrlParams } from '../SQLEditor';

const POLL_INTERVAL_MS = 750;

const ResultsTable: React.FC = () => {
  const { urlParams } = useUrlParams<LogQueryUrlParams>();
  const { data, loading, error, startPolling, stopPolling } = useGetLogQueryResults({
    skip: !urlParams.queryId,
    variables: {
      input: {
        queryId: urlParams.queryId,
        pageSize: DEFAULT_LARGE_PAGE_SIZE,
      },
    },
  });

  React.useEffect(() => {
    if (data) {
      const { status } = data.getLogQuery.query;
      if (status === LogQueryStatus.Running) {
        startPolling(POLL_INTERVAL_MS);
      } else {
        stopPolling();
      }
    }
  }, [data]);

  const isQueryRunning = loading || data?.getLogQuery.query.status === LogQueryStatus.Running;
  if (isQueryRunning) {
    return <TablePlaceholder />;
  }

  const hasQueryFailed = error || data?.getLogQuery.query.status === LogQueryStatus.Failed;
  if (hasQueryFailed) {
    const errorMessage = error ? extractErrorMessage(error) : data?.getLogQuery.error?.message;
    return (
      <Flex justifyContent="center" alignItems="center" my={100}>
        <Text size="large" color="red300" is="p" textAlign="center" backgroundColor="red50" p={6}>
          {errorMessage}
        </Text>
      </Flex>
    );
  }

  if (data) {
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
  }

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
};

export default ResultsTable;
