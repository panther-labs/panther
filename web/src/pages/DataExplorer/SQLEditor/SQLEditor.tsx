import React from 'react';
import { Box, Button, useSnackbar } from 'pouncejs';
import Editor, { Completion } from 'Components/Editor';
import { shouldSaveData } from 'Helpers/connection';
import storage from 'Helpers/storage';
import { extractErrorMessage } from 'Helpers/utils';
import { useLoadAllSchemaEntities } from './graphql/loadAllSchemaEntities.generated';
import { useDataExplorerContext } from '../DataExplorerContext';
import { useRunQuery } from './graphql/runQuery.generated';
import { useCancelLogQuery } from './graphql/cancelLogQuery.generated';
import { useGetSqlForQuery } from './graphql/getSqlForQuery.generated';

// A key to help persist sql text within the same session (resets for new sessions)
const SQL_STORAGE_KEY = 'panther.dataAnalytics.dataExplorer.sql';
const MIN_LINES = 19;

const SQLEditor: React.FC = () => {
  const [value, setValue] = React.useState(storage.session.read(SQL_STORAGE_KEY) || '');
  const { pushSnackbar } = useSnackbar();
  const {
    state: { selectedDatabase, queryStatus, queryId },
    dispatch,
  } = useDataExplorerContext();

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

  // Restore SQL for query if it already existed
  useGetSqlForQuery({
    skip: !queryId,
    variables: {
      input: {
        queryId,
      },
    },
    onCompleted: data => {
      // FIXME: Apollo has a bug and this callback gets executed even when `skip: true`. That's why
      // we have the `&& data` check. Other than that, the `if (!value)` part is cause we don't want
      // to override any value if the user has already started typing
      // https://github.com/apollographql/apollo-client/issues/6122
      if (!value && data) {
        setValue(data.getLogQuery.query.sql);
      }
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

  // When the component unmounts, store the last value in the session storage in case the user
  // navigated away by mistake. This will help us restore each session next time
  React.useEffect(() => {
    return () => storage.session.write(SQL_STORAGE_KEY, value);
  }, [value]);

  return (
    <Box>
      <Editor
        fallback={<Box width="100%" bg="grey500" height={MIN_LINES * 19} />}
        placeholder="Run any SQL query. For example: select * from panther_logs.aws_alb;"
        minLines={MIN_LINES}
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
          onClick={() => {
            cancelQuery();
            dispatch({ type: 'QUERY_CANCELED' });
          }}
        >
          Cancel
        </Button>
      ) : (
        <Button
          size="large"
          variant="primary"
          mt={6}
          disabled={!value || !selectedDatabase || isProvisioningQuery}
          onClick={() => {
            runQuery();
            dispatch({ type: 'QUERY_PROVISIONING' });
          }}
        >
          Run Query
        </Button>
      )}
    </Box>
  );
};

export default React.memo(SQLEditor);
