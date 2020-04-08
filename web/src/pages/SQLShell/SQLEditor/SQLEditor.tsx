import React from 'react';
import { Box, Button, useSnackbar } from 'pouncejs';
import Editor from 'Components/Editor';
import { shouldSaveData } from 'Helpers/connection';
import { extractErrorMessage } from 'Helpers/utils';
import { useLoadAllSchemaEntities } from './graphql/loadAllSchemaEntities.generated';

const PLACEHOLDER = `Run any SQL query. For example: SELECT * FROM panther_logs.aws_alb;`;

const SQLEditor: React.FC = () => {
  const { pushSnackbar } = useSnackbar();
  useLoadAllSchemaEntities({
    skip: shouldSaveData(),
    onError: error =>
      pushSnackbar({
        variant: 'warning',
        title: 'SQL autocomplete is disabled',
        description: extractErrorMessage(error),
      }),
  });

  const minLines = 19;
  return (
    <Box>
      <Editor
        fallback={<Box width="100%" bg="grey500" height={minLines * 16} />}
        placeholder={PLACEHOLDER}
        minLines={minLines}
        mode="sql"
        width="100%"
      />
      <Button size="large" variant="primary" mt={6}>
        Run Query
      </Button>
    </Box>
  );
};

export default SQLEditor;
