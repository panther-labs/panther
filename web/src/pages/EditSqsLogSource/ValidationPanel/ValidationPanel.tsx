/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import { Button, Flex, Heading, Text } from 'pouncejs';
import Panel from 'Components/Panel';
import urls from 'Source/urls';
import useRouter from 'Hooks/useRouter';

interface ValidationPanelProps {
  skipValidation: () => void;
  queueUrl: string;
}

const ValidationPanel: React.FC<ValidationPanelProps> = ({ skipValidation, queueUrl }) => {
  const { history } = useRouter();

  return (
    <Panel title="Setup SQS queue">
      <Flex direction="column" height={550} justify="center" align="center">
        <Heading as="h2" mb={2}>
          You need to setup the SQS queue
        </Heading>
        <Text color="gray-300" mb={10}>
          This is the url of the SQS queue we created for you:
        </Text>
        <Text color="gray-300" fontSize="small-medium" mb={10}>
          {queueUrl}
        </Text>
      </Flex>
      <Flex justify="flex-end" spacing={3}>
        <Button variant="outline" onClick={() => skipValidation()}>
          Skip
        </Button>
        <Button onClick={() => history.push(urls.logAnalysis.sources.list())}>Done</Button>
      </Flex>
    </Panel>
  );
};

export default ValidationPanel;
