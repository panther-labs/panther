import React from 'react';
import { Box } from 'pouncejs';
import Editor from 'Components/Editor';

const PLACEHOLDER = `
-- SELECT * FROM default.cloudfront_logs limit 10;
`;

const SQLEditor: React.FC = () => {
  const minLines = 16;
  return (
    <Editor
      fallback={<Box width="100%" bg="grey500" height={minLines * 16} />}
      placeholder={PLACEHOLDER}
      minLines={minLines}
      mode="sql"
      width="100%"
    />
  );
};

export default SQLEditor;
