import React from 'react';
import { Card, Grid } from 'pouncejs';
import SQLEditor from './SQLEditor';
import Browser from './Browser';

const SQLShellPage: React.FC = () => {
  return (
    <Grid gridGap={4} gridTemplateColumns="1fr 3fr">
      <Browser />
      <Card p={9}>
        <SQLEditor />
      </Card>
    </Grid>
  );
};

export default SQLShellPage;
