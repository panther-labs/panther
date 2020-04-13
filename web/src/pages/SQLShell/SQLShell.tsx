import React from 'react';
import { Box, Card, Grid } from 'pouncejs';
import Panel from 'Components/Panel';
import SQLEditor from './SQLEditor';
import Browser from './Browser';
import ResultsTable from './ResultsTable';
import { withSQLShellContext } from './SQLShellContext';

const SQLShellPage: React.FC = () => {
  return (
    <Box>
      <Grid gridGap={4} gridTemplateColumns="1fr 3fr" mb={4}>
        <Browser />
        <Card p={9}>
          <SQLEditor />
        </Card>
      </Grid>
      <Box mb={4} minHeight={400}>
        <Panel title="Results" size="large">
          <ResultsTable />
        </Panel>
      </Box>
    </Box>
  );
};

export default withSQLShellContext(React.memo(SQLShellPage));
