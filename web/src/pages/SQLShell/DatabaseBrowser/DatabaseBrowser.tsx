import React from 'react';
import { Box, Card, Combobox, useSnackbar } from 'pouncejs';
import { useListLogDatabases } from 'Pages/SQLShell/DatabaseBrowser/graphql/listLogDatabases.generated';
import { extractErrorMessage } from 'Helpers/utils';

const DatabaseBrowser: React.FC = () => {
  const [selectedDatabase, selectDatabase] = React.useState<string>();
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
    <Card height={507} is="aside">
      <Box is="header" p={6}>
        <Combobox
          label="Select Database"
          items={data?.listLogDatabases.map(db => db.name) ?? []}
          onChange={selectDatabase}
          value={selectedDatabase}
        />
      </Box>
    </Card>
  );
};

export default DatabaseBrowser;
