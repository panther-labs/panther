import React from 'react';
import { Box, useSnackbar } from 'pouncejs';
import { extractErrorMessage } from 'Helpers/utils';
import TablePlaceholder from 'Components/TablePlaceholder';
import { useBrowserContext } from './BrowserContext';
import { useListTablesForDatabase } from './graphql/listTablesForDatabase.generated';
import TableListItem from './TableListItem';

const TableList: React.FC = () => {
  const { pushSnackbar } = useSnackbar();
  const { selectTable, selectedDatabase, searchValue } = useBrowserContext();
  const { data, loading } = useListTablesForDatabase({
    variables: {
      name: selectedDatabase,
    },
    onError: error =>
      pushSnackbar({
        variant: 'error',
        title: "Couldn't fetch your databases",
        description: extractErrorMessage(error),
      }),
  });

  if (loading) {
    return (
      <Box m={6}>
        <TablePlaceholder rowCount={8} rowHeight={30} rowGap={15} />
      </Box>
    );
  }

  return (
    <Box overflowY="scroll" is="ul" py={2} height="100%">
      {data?.getLogDatabase.tables
        .filter(({ name }) => name.includes(searchValue))
        .map(({ name }) => (
          <TableListItem key={name} name={name} onClick={selectTable} />
        ))}
    </Box>
  );
};

export default TableList;
