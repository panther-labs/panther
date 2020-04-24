import React from 'react';
import { Combobox, useSnackbar } from 'pouncejs';
import { extractErrorMessage } from 'Helpers/utils';
import { useListLogDatabases } from './graphql/listLogDatabases.generated';
import { useDataExplorerContext } from '../../DataExplorerContext';

const DatabaseSelector: React.FC = () => {
  const { pushSnackbar } = useSnackbar();
  const {
    state: { selectedDatabase },
    dispatch,
  } = useDataExplorerContext();

  const { data } = useListLogDatabases({
    onError: error =>
      pushSnackbar({
        variant: 'error',
        title: "Couldn't fetch your databases",
        description: extractErrorMessage(error),
      }),
  });

  // There must always be one database selected. If it's not, arbitrarily select the 1st one
  React.useEffect(() => {
    if (data && !selectedDatabase) {
      dispatch({
        type: 'SELECT_DATABASE',
        payload: { database: data.listLogDatabases[0]?.name },
      });
    }
  }, [data, selectedDatabase, dispatch]);

  return (
    <Combobox
      label="Select Database"
      items={data?.listLogDatabases.map(db => db.name) ?? []}
      onChange={database => dispatch({ type: 'SELECT_DATABASE', payload: { database } })}
      value={selectedDatabase}
      inputProps={{ placeholder: 'Select a database...' }}
    />
  );
};

export default DatabaseSelector;
