import React from 'react';
import { Combobox, useSnackbar } from 'pouncejs';
import { extractErrorMessage } from 'Helpers/utils';
import { useListLogDatabases } from './graphql/listLogDatabases.generated';
import { useSQLShellContext } from '../../SQLShellContext';

const DatabaseSelector: React.FC = () => {
  const { selectDatabase, selectedDatabase } = useSQLShellContext();
  const { pushSnackbar } = useSnackbar();
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
      selectDatabase(data.listLogDatabases[0]?.name);
    }
  }, [data, selectedDatabase, selectDatabase]);

  return (
    <Combobox
      label="Select Database"
      items={data?.listLogDatabases.map(db => db.name) ?? []}
      onChange={selectDatabase}
      value={selectedDatabase}
      inputProps={{ placeholder: 'Select a database...' }}
    />
  );
};

export default DatabaseSelector;
