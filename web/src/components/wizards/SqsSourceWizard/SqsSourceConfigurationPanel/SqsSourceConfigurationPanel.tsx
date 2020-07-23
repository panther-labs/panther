/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import { Box, Flex, Heading, Text } from 'pouncejs';
import ErrorBoundary from 'Components/ErrorBoundary';
import { FastField, Field, useFormikContext } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import { LOG_TYPES } from 'Source/constants';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import { SqsLogSourceWizardValues } from '../SqsSourceWizard';

const SqsSourceConfigurationPanel: React.FC = () => {
  const { initialValues } = useFormikContext<SqsLogSourceWizardValues>();

  return (
    <Box width={460} m="auto">
      <Heading as="h2" m="auto" mb={2}>
        {initialValues.integrationId ? 'Update the SQS source' : "Let's start with the basics"}
      </Heading>
      <Text color="gray-300" mb={10}>
        {initialValues.integrationId
          ? 'Feel free to make any changes to your SQS log source'
          : 'We need to know where to get your logs from'}
      </Text>
      <ErrorBoundary>
        <Flex direction="column" spacing={4}>
          <Field
            name="integrationLabel"
            as={FormikTextInput}
            label="* Name"
            placeholder="A nickname for this SQS log source"
            required
          />
          <FastField
            as={FormikMultiCombobox}
            searchable
            label="* Log Types"
            name="logTypes"
            items={LOG_TYPES}
            placeholder="Which log types should we monitor?"
          />
          <FastField
            as={FormikMultiCombobox}
            label="* Allowed Principals"
            name="allowedPrincipals"
            searchable
            allowAdditions
            items={[]}
            placeholder="Which are the allowed principals should we monitor?"
          />
          <FastField
            as={FormikMultiCombobox}
            label="* Allowed ARNs"
            name="allowedSourceArns"
            searchable
            allowAdditions
            items={[]}
            placeholder="Which are the allowed ARNs?"
          />
        </Flex>
      </ErrorBoundary>
    </Box>
  );
};

export default SqsSourceConfigurationPanel;
