import React from 'react';
import { Combobox, useSnackbar } from 'pouncejs';
import { useListLogDatabases } from 'Pages/SQLShell/Browser/graphql/listLogDatabases.generated';
import { extractErrorMessage } from 'Helpers/utils';
import { useBrowserContext } from './BrowserContext';

const DatabaseSelector: React.FC = () => {
  const { selectDatabase, selectedDatabase } = useBrowserContext();
  const { pushSnackbar } = useSnackbar();
  const { data } = useListLogDatabases({
    onError: error =>
      pushSnackbar({
        variant: 'error',
        title: "Couldn't fetch your databases",
        description: extractErrorMessage(error),
      }),
  });

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
