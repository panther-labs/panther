import React from 'react';
import { Box, useSnackbar } from 'pouncejs';
import { extractErrorMessage } from 'Helpers/utils';
import TablePlaceholder from 'Components/TablePlaceholder';
import { useDataExplorerContext } from '../../DataExplorerContext';
import { useListTablesForDatabase } from './graphql/listTablesForDatabase.generated';
import TableListItem from './TableListItem';

const TableList: React.FC = () => {
  const { pushSnackbar } = useSnackbar();
  const {
    state: { selectedDatabase, searchValue },
    dispatch,
  } = useDataExplorerContext();
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

  const selectTable = React.useCallback(
    table => dispatch({ type: 'SELECT_TABLE', payload: { table } }),
    [dispatch]
  );

  if (loading) {
    return (
      <Box m={6}>
        <TablePlaceholder rowCount={8} rowHeight={30} rowGap={15} />
      </Box>
    );
  }

  return (
    <Box overflowY="scroll" as="ul" py={2} height="100%">
      {data?.getLogDatabase.tables
        .filter(({ name }) => name.includes(searchValue))
        .map(({ name }) => (
          <TableListItem key={name} name={name} onClick={selectTable} />
        ))}
    </Box>
  );
};

export default TableList;
