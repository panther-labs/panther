import React from 'react';
import { Box, Button, useSnackbar } from 'pouncejs';
import Editor, { Completion } from 'Components/Editor';
import { shouldSaveData } from 'Helpers/connection';
import { extractErrorMessage } from 'Helpers/utils';
import { useLoadAllSchemaEntities } from './graphql/loadAllSchemaEntities.generated';

const PLACEHOLDER = `Run any SQL query. For example: select * from panther_logs.aws_alb;`;

const minLines = 19;
const fallback = <Box width="100%" bg="grey500" height={minLines * 19} />;

const SQLEditor: React.FC = () => {
  const { pushSnackbar } = useSnackbar();
  const { data } = useLoadAllSchemaEntities({
    skip: shouldSaveData(),
    onError: error =>
      pushSnackbar({
        variant: 'warning',
        title: 'SQL autocomplete is disabled',
        description: extractErrorMessage(error),
      }),
  });

  const completions = React.useMemo(() => {
    const acc = new Set<Completion>();
    if (data) {
      data.listLogDatabases.forEach(database => {
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
  }, [data]);

  return (
    <Box>
      <Editor
        fallback={fallback}
        placeholder={PLACEHOLDER}
        minLines={minLines}
        mode="sql"
        width="100%"
        completions={completions}
      />
      <Button size="large" variant="primary" mt={6}>
        Run Query
      </Button>
    </Box>
  );
};

export default React.memo(SQLEditor);
