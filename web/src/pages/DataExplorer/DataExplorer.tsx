import React from 'react';
import { Box, Card, Grid, Text } from 'pouncejs';
import SQLEditor from './SQLEditor';
import Browser from './Browser';
import Results from './Results';
import { useDataExplorerContext, withDataExplorerContext } from './DataExplorerContext';

const DataExplorerPage: React.FC = () => {
  const {
    state: { globalErrorMessage },
  } = useDataExplorerContext();

  return (
    <Box>
      {globalErrorMessage && (
        <Text
          size="large"
          color="red300"
          as="p"
          textAlign="center"
          backgroundColor="red50"
          p={6}
          mb={4}
        >
          {globalErrorMessage}
        </Text>
      )}
      <Grid gap={4} templateColumns="1fr 3fr" mb={4}>
        <Browser />
        <Card p={9}>
          <SQLEditor />
        </Card>
      </Grid>
      <Box mb={4} minHeight={400}>
        <Results />
      </Box>
    </Box>
  );
};

export default withDataExplorerContext(DataExplorerPage);
