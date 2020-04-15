import React from 'react';
import { Box, Button, useSnackbar } from 'pouncejs';
import Editor, { Completion } from 'Components/Editor';
import { shouldSaveData } from 'Helpers/connection';
import { extractErrorMessage } from 'Helpers/utils';
import { useLoadAllSchemaEntities } from './graphql/loadAllSchemaEntities.generated';
import { useSQLShellContext } from '../SQLShellContext';
import { useRunQuery } from './graphql/runQuery.generated';
import { useCancelLogQuery } from './graphql/cancelLogQuery.generated';

const minLines = 19;

const SQLEditor: React.FC = () => {
  const [value, setValue] = React.useState('');
  const { pushSnackbar } = useSnackbar();
  const {
    state: { selectedDatabase, queryStatus, queryId },
    dispatch,
  } = useSQLShellContext();

  const [runQuery, { loading: isProvisioningQuery }] = useRunQuery({
    variables: {
      input: {
        databaseName: selectedDatabase,
        sql: value,
      },
    },
    onCompleted: data => {
      if (data.executeAsyncLogQuery.error) {
        dispatch({
          type: 'QUERY_ERRORED',
          payload: { message: data.executeAsyncLogQuery.error.message },
        });
      } else {
        dispatch({
          type: 'QUERY_RUNNING',
          payload: { queryId: data.executeAsyncLogQuery.queryId },
        });
      }
    },
    onError: () => {
      dispatch({ type: 'QUERY_ERRORED', payload: { message: "Couldn't execute your Query" } });
    },
  });

  const [cancelQuery, { loading: isCancelingQuery }] = useCancelLogQuery({
    variables: {
      input: {
        queryId,
      },
    },
    onCompleted: data => {
      if (data.cancelLogQuery.error) {
        pushSnackbar({
          variant: 'error',
          title: "Couldn't cancel your Query",
          description: data.cancelLogQuery.error.message,
        });
      }
    },
    onError: () => {
      pushSnackbar({
        variant: 'error',
        title: "Couldn't cancel your Query",
        description: 'It will continue to be executed in the background',
      });
    },
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

  // When `runQuery` is called set the status to "provisioning" until we get a queryId back, in which
  // case the `onComplete` handler of the `runQuery` will make sure to set the correct query status
  React.useEffect(() => {
    if (isProvisioningQuery) {
      dispatch({ type: 'QUERY_PROVISIONING' });
    }
  }, [isProvisioningQuery]);

  // When `cancelQuery` is called set the status to "null" to simulate optimistic cancellation. In
  // any case (regardless of whether the query was cancelled) the query status should return to a
  // pristine state in order to allow the user to write a new query
  React.useEffect(() => {
    if (isCancelingQuery) {
      dispatch({ type: 'QUERY_CANCELED' });
    }
  }, [isCancelingQuery]);

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
      {queryStatus === 'running' ? (
        <Button
          size="large"
          variant="default"
          color="red300"
          mt={6}
          disabled={isCancelingQuery}
          onClick={() => cancelQuery()}
        >
          Cancel
        </Button>
      ) : (
        <Button
          size="large"
          variant="primary"
          mt={6}
          disabled={!value || !selectedDatabase || isProvisioningQuery}
          onClick={() => runQuery()}
        >
          Run Query
        </Button>
      )}
    </Box>
  );
};

export default React.memo(SQLEditor);
