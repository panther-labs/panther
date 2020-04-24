import React from 'react';
import { Box, Card, Flex, Text } from 'pouncejs';
import ErrorBoundary from 'Components/ErrorBoundary';
import TableList from './TableList';
import DatabaseSelector from './DatabaseSelector';
import { useSQLShellContext } from '../SQLShellContext';
import ColumnList from './ColumnList';
import Search from './Search';

const Browser: React.FC = () => {
  const {
    state: { selectedDatabase, selectedTable },
  } = useSQLShellContext();

  return (
    <Card height={507} as="aside" overflow="hidden">
      <ErrorBoundary>
        <Flex direction="column" height="100%">
          <Box as="header" p={6}>
            <Box mb={4} as="section">
              <DatabaseSelector />
            </Box>
            <Box as="section">
              <Search />
            </Box>
          </Box>
          <Box overflowY="hidden" width="100%">
            {!selectedDatabase && (
              <Text size="large" color="grey200" textAlign="center" mt={100}>
                Nothing selected yet
              </Text>
            )}
            {!!selectedDatabase && !selectedTable && (
              <ErrorBoundary>
                <TableList />
              </ErrorBoundary>
            )}
            {!!selectedDatabase && selectedTable && (
              <ErrorBoundary>
                <ColumnList />
              </ErrorBoundary>
            )}
          </Box>
        </Flex>
      </ErrorBoundary>
    </Card>
  );
};

export default Browser;
