/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
      {initialValues.integrationId ? (
        <React.Fragment>
          <Text color="gray-300" mb={2}>
            You need to send events on this queue url for Panther to process them:
          </Text>
          <Text fontSize="small" mb={10}>
            {initialValues.queueUrl}
          </Text>
          <Text color="gray-300" mb={4}>
            Feel free to make any changes to your SQS log source
          </Text>
        </React.Fragment>
      ) : (
        <Text color="gray-300" mb={10}>
          We need to know where to get your logs from
        </Text>
      )}
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
            label="Allowed Principals"
            name="allowedPrincipals"
            searchable
            allowAdditions
            items={[]}
            placeholder="Which are the allowed principals should we monitor?"
          />
          <FastField
            as={FormikMultiCombobox}
            label="Allowed ARNs"
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
