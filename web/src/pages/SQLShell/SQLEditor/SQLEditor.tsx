import React from 'react';
import { Box, useSnackbar } from 'pouncejs';
import SubmitButton from 'Components/buttons/SubmitButton';
import Editor, { Completion } from 'Components/Editor';
import { shouldSaveData } from 'Helpers/connection';
import { extractErrorMessage } from 'Helpers/utils';
import useUrlParams from 'Hooks/useUrlParams';
import { useLoadAllSchemaEntities } from './graphql/loadAllSchemaEntities.generated';
import { useSQLShellContext } from '../SQLShellContext';
import { useRunQuery } from './graphql/runQuery.generated';

const minLines = 19;

export interface LogQueryUrlParams {
  queryId?: string;
}

const SQLEditor: React.FC = () => {
  const { updateUrlParams } = useUrlParams<LogQueryUrlParams>();
  const [value, setValue] = React.useState('');
  const { selectedDatabase } = useSQLShellContext();
  const { pushSnackbar } = useSnackbar();

  const [runQuery, { loading: isSubmittingQueryRequest }] = useRunQuery({
    variables: {
      input: {
        databaseName: selectedDatabase,
        sql: value,
      },
    },
    onCompleted: data => updateUrlParams({ queryId: data.executeAsyncLogQuery.queryId }),
    onError: error =>
      pushSnackbar({
        variant: 'error',
        title: "Couldn't execute your Query",
        description: extractErrorMessage(error),
      }),
  });

  // Fetch Autocomplete suggestions
  const { data: schemaData } = useLoadAllSchemaEntities({
    skip: shouldSaveData(),
    onError: error =>
      pushSnackbar({
        variant: 'warning',
        title: 'SQL autocomplete is disabled',
        description: extractErrorMessage(error),
      }),
  });

  // Create proper completion data
  const completions = React.useMemo(() => {
    const acc = new Set<Completion>();
    if (schemaData) {
      schemaData.listLogDatabases.forEach(database => {
        acc.add({ value: database.name, type: 'database' });
        database.tables.forEach(table => {
          acc.add({ value: table.name, type: 'table' });
          table.columns.forEach(column => {
            acc.add({ value: column.name, type: column.type });
          });
        });
      });
    }

    return [...acc];
  }, [schemaData]);

  return (
    <Box>
      <Editor
        fallback={<Box width="100%" bg="grey500" height={minLines * 19} />}
        placeholder="Run any SQL query. For example: select * from panther_logs.aws_alb;"
        minLines={minLines}
        mode="sql"
        width="100%"
        completions={completions}
        onChange={setValue}
        value={value}
      />
      <SubmitButton
        mt={6}
        disabled={!value || !selectedDatabase || isSubmittingQueryRequest}
        submitting={isSubmittingQueryRequest}
        onClick={() => runQuery()}
      >
        Run Query
      </SubmitButton>
    </Box>
  );
};

export default React.memo(SQLEditor);
