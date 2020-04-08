import React from 'react';
import { Box, Flex, Icon, IconButton, Text, useSnackbar } from 'pouncejs';
import { extractErrorMessage } from 'Helpers/utils';
import TablePlaceholder from 'Components/TablePlaceholder';
import { useBrowserContext } from './BrowserContext';
import { useListColumnsForTable } from './graphql/listColumnsForTable.generated';
import ColumnListItem from './ColumnListItem';

const ColumnList: React.FC = () => {
  const { pushSnackbar } = useSnackbar();
  const {
    selectedTable,
    selectedDatabase,
    selectedColumn,
    selectColumn,
    selectTable,
    searchValue,
  } = useBrowserContext();

  const { data, loading } = useListColumnsForTable({
    returnPartialData: true,
    variables: {
      input: {
        databaseName: selectedDatabase,
        name: selectedTable,
      },
    },
    onError: error =>
      pushSnackbar({
        variant: 'error',
        title: "Couldn't fetch the table's columns",
        description: extractErrorMessage(error),
      }),
  });

  const columns = data?.getLogDatabaseTable?.columns;
  return (
    <React.Fragment>
      <Flex alignItems="center" mx={2} is="li">
        <IconButton variant="default" onClick={() => selectTable(null)}>
          <Icon type="arrow-back" />
        </IconButton>
        <Text color="black" fontWeight="bold" size="medium" ml={2}>
          {selectedTable}
        </Text>
      </Flex>
      {loading && !columns && (
        <Box m={6}>
          <TablePlaceholder rowCount={8} rowHeight={30} rowGap={15} />
        </Box>
      )}
      {columns && (
        <Box overflowY="scroll" is="ul" py={2} height="100%">
          {columns
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
      )}
    </React.Fragment>
  );
};

export default ColumnList;
