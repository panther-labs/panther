import React from 'react';
import { Box, Flex, Icon, IconButton, Text } from 'pouncejs';
import { useBrowserContext } from './BrowserContext';
import { useListColumnsForTable } from './graphql/listColumnsForTable.generated';
import ColumnListItem from './ColumnListItem';

const ColumnList: React.FC = () => {
  const {
    selectedTable,
    selectedDatabase,
    selectedColumn,
    selectColumn,
    selectTable,
    searchValue,
  } = useBrowserContext();

  const { data } = useListColumnsForTable({
    fetchPolicy: 'cache-only', // will be there from the table listing. Throw if it's not
    variables: {
      input: {
        databaseName: selectedDatabase,
        name: selectedTable,
      },
    },
  });

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
      <Box overflowY="scroll" is="ul" py={2} height="100%">
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
