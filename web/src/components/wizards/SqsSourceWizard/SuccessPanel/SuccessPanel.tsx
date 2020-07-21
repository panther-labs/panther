/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import { Flex, FormError, Heading, Text } from 'pouncejs';
import SubmitButton from 'Components/buttons/SubmitButton';
import { useFormikContext } from 'formik';
import { SqsLogSourceWizardValues } from '../SqsSourceWizard';

const SuccessPanel: React.FC = () => {
  const { initialValues, setStatus, status } = useFormikContext<SqsLogSourceWizardValues>();

  // Reset error when the users navigate away from this stpe (so that when they come back, the
  // previous error isn't presented at them)
  React.useEffect(() => {
    return () => setStatus({ ...status, errorMessage: null });
  }, []);

  return (
    <Flex justify="center" align="center" direction="column" my={190} mx="auto" width={400}>
      <Heading as="h2" m="auto" mb={5}>
        Almost done!
      </Heading>
      <Text color="gray-300" mb={10} textAlign="center">
        {initialValues.integrationId
          ? 'Click the button below to validate your changes & update your source!'
          : 'After setting up your SQS configuration, click on the button below to complete the setup!'}
      </Text>
      <SubmitButton fullWidth>
        {initialValues.integrationId ? 'Update Source' : 'Save Source'}
      </SubmitButton>
      {status.errorMessage && <FormError mt={6}>{status.errorMessage}</FormError>}
    </Flex>
  );
};

export default SuccessPanel;
