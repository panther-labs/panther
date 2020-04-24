import React from 'react';
import { Box, Flex, Icon, IconButton, Text } from 'pouncejs';
import { useDataExplorerContext } from '../../DataExplorerContext';
import { useListColumnsForTable } from './graphql/listColumnsForTable.generated';
import ColumnListItem from './ColumnListItem';

const ColumnList: React.FC = () => {
  const {
    state: { selectedTable, selectedDatabase, selectedColumn, searchValue },
    dispatch,
  } = useDataExplorerContext();

  const { data } = useListColumnsForTable({
    fetchPolicy: 'cache-only', // will be there from the table listing. Throw if it's not
    variables: {
      input: {
        databaseName: selectedDatabase,
        name: selectedTable,
      },
    },
  });

  const selectColumn = React.useCallback(
    column => dispatch({ type: 'SELECT_COLUMN', payload: { column } }),
    [dispatch]
  );

  return (
    <React.Fragment>
      <Flex align="center" mx={2} as="li">
        <IconButton
          variant="default"
          onClick={() => dispatch({ type: 'SELECT_TABLE', payload: { table: null } })}
        >
          <Icon type="arrow-back" />
        </IconButton>
        <Text color="black" fontWeight="bold" size="medium" ml={2}>
          {selectedTable}
        </Text>
      </Flex>
      <Box overflowY="scroll" as="ul" py={2} height="100%">
        {data?.getLogDatabaseTable?.columns
          .filter(({ name }) => name.includes(searchValue))
          .map(({ name, type, description }) => {
            return (
              <ColumnListItem
                key={name}
                name={name}
                type={type}
                description={description}
                isSelected={selectedColumn === name}
                isPristine={selectedColumn === null}
                onClick={selectColumn}
              />
            );
          })}
      </Box>
    </React.Fragment>
  );
};

export default ColumnList;
