import React from 'react';
import { Box, Flex, Heading, Icon, Spinner, Table } from 'pouncejs';
import WarningImg from 'Assets/illustrations/warning.svg';
import BlankCanvasImg from 'Assets/illustrations/blank-canvas.svg';
import { GetLogQueryOutput } from 'Generated/schema';
import TablePlaceholder from 'Components/TablePlaceholder';
import { useDataExplorerContext } from 'Pages/DataExplorer/DataExplorerContext';
import dayjs from 'dayjs';
import { isNumber } from 'Helpers/utils';

export interface ResultsTableProps {
  isFetchingMore: boolean;
  results: GetLogQueryOutput['results'];
}

const ResultsTable: React.FC<ResultsTableProps> = ({ isFetchingMore, results }) => {
  const startTime = React.useRef(dayjs());
  const {
    state: { queryStatus },
  } = useDataExplorerContext();

  const isPristine = queryStatus === null;
  const hasErrored = queryStatus === 'errored';
  const isProvisioning = queryStatus === 'provisioning';
  const isRunning = queryStatus === 'running';

  // Start the timer for how much time the query is running only when the status gets to "running".
  // This is only gonna happen once since the transition from "something" to "running" can only
  // happen once by default
  React.useEffect(() => {
    if (isRunning) {
      startTime.current = dayjs();
    }
  }, [isRunning]);

  // Original state, meaning that no query is present
  if (isPristine) {
    return (
      <Flex justify="center" align="center" direction="column" color="grey200" my={125}>
        <Icon size="large" type="search" />
        <Heading size="medium" my={6}>
          Write a query to see results
        </Heading>
      </Flex>
    );
  }

  // Query had errors
  if (hasErrored) {
    return (
      <Flex justify="center" align="center" direction="column">
        <Box my={10}>
          <img alt="Road works Illustration" src={WarningImg} width="auto" height={200} />
        </Box>
        <Heading size="medium" color="grey200" mb={6}>
          Your query has errors. Look up.
        </Heading>
      </Flex>
    );
  }

  // Query is being submitted to the server and we are waiting to get back a `queryId` to use it
  // to "poll" for results
  if (isProvisioning) {
    return (
      <Flex justify="center" align="center" my={125}>
        <Spinner size="medium" />
        <Heading size="medium" ml={8} color="grey300">
          Provisioning...
        </Heading>
      </Flex>
    );
  }

  // Gotten back a `queryId` and we are on the polling phase, were we are waiting for results
  if (isRunning) {
    return (
      <Flex justify="center" align="center" my={125}>
        <Spinner size="medium" />
        <Heading size="medium" ml={8} color="grey300">
          Running Query... Elapsed Time: {dayjs().diff(startTime.current, 'second')}s
        </Heading>
      </Flex>
    );
  }

  // We have results, but they are empty
  if (!results.length) {
    return (
      <Flex justify="center" align="center" direction="column">
        <Box my={10}>
          <img alt="Black Canvas Illustration" src={BlankCanvasImg} width="auto" height={150} />
        </Box>
        <Heading size="medium" color="grey200" mb={6}>
          No results were found for your query
        </Heading>
      </Flex>
    );
  }

  // Render a table and the "fetching more" placeholder. This is different than "loading" or the
  // "running" state. It has to be handled through a separate prop
  return (
    <Box overflowX="scroll">
      <Table size="small">
        <Table.Head>
          <Table.Row>
            {results[0].map(col => (
              <Table.HeaderCell key={col.key} align={isNumber(col.value) ? 'right' : 'left'}>
                {col.key}
              </Table.HeaderCell>
            ))}
          </Table.Row>
        </Table.Head>
        <Table.Body>
          {results.map((row, index) => (
            <Table.Row key={index}>
              {row.map(col => (
                <Table.Cell
                  key={`${index}-${col.value}`}
                  wrapText="nowrap"
                  align={isNumber(col.value) ? 'right' : 'left'}
                >
                  {col.value === null ? 'NULL' : col.value}
                </Table.Cell>
              ))}
            </Table.Row>
          ))}
        </Table.Body>
      </Table>
      {isFetchingMore && (
        <Box mt={8}>
          <TablePlaceholder rowCount={10} />
        </Box>
      )}
    </Box>
  );
};

export default React.memo(ResultsTable);
