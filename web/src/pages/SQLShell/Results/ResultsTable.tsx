import React from 'react';
import { Box, Flex, Heading, Icon, Table } from 'pouncejs';
import WarningImg from 'Assets/illustrations/warning.svg';
import BlankCanvasImg from 'Assets/illustrations/blank-canvas.svg';
import { GetLogQueryOutput } from 'Generated/schema';
import TablePlaceholder from 'Components/TablePlaceholder';

export interface ResultsTableProps {
  state: 'hasErrored' | 'initial' | 'isFetching';
  results: GetLogQueryOutput['results'];
}

const ResultsTable: React.FC<ResultsTableProps> = ({ state, results }) => {
  if (state === 'initial') {
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

  if (state === 'hasErrored') {
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

  if (!results.length) {
    if (state === 'isFetching') {
      return <TablePlaceholder />;
    }

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

  // Converts list of lists of {key,value} to a single flattened list with all column keys
  // merged into a single object. I.e. [[{key: 'x', value: '1 },{key: 'y', value: '2 }]]
  // would become [{ x: '1', y: '2'}]
  const items = results.map(cols =>
    cols.reduce((acc, col) => ({ ...acc, [col.key]: col.value }), {})
  );

  // Dynamically create column headers and keys.
  const columns =
    results[0]?.map(col => ({
      key: col.key,
      header: col.key,
    })) ?? [];

  return (
    <Box overflowX="scroll">
      <Table items={items} columns={columns} />
      {state === 'isFetching' && (
        <Box mt={4}>
          <TablePlaceholder />
        </Box>
      )}
    </Box>
  );
};

export default React.memo(ResultsTable);
