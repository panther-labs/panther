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

import { AbstractButton, Box, Heading, Text } from 'pouncejs';
import ErrorBoundary from 'Components/ErrorBoundary';
import { Field, useFormikContext } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import React from 'react';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import { LOG_TYPES } from 'Source/constants';
import { LogSourceWizardValues } from '../LogSourceWizard';

const SourceConfigurationPanel: React.FC = () => {
  const { initialValues, values } = useFormikContext<LogSourceWizardValues>();
  const [isAdvancedConfigVisible, showAdvancedConfig] = React.useState(
    Boolean(values.s3Prefix) || Boolean(values.kmsKey)
  );

  return (
    <Box width={460} m="auto">
      <Heading size="medium" m="auto" mb={2} color="grey400">
        {initialValues.integrationId ? 'Update source' : "Let's start with the basics"}
      </Heading>
      <Text size="large" color="grey200" mb={10} as="p">
        {initialValues.integrationId
          ? 'Feel free to make any changes to your log source'
          : 'We need to know where to get your logs from'}
      </Text>
      <ErrorBoundary>
        <Field
          name="integrationLabel"
          as={FormikTextInput}
          label="Name"
          placeholder="A nickname for this log analysis source"
          aria-required
          mb={6}
        />
        <Field
          name="awsAccountId"
          as={FormikTextInput}
          label="Account ID"
          placeholder="The AWS Account ID that the S3 log bucket lives in"
          disabled={!!initialValues.integrationId}
          aria-required
          mb={6}
        />
        <Field
          name="s3Bucket"
          as={FormikTextInput}
          label="Bucket Name"
          aria-required
          placeholder="The name of the S3 bucket that holds the logs"
          mb={6}
        />
        <Field
          as={FormikMultiCombobox}
          searchable
          label="Log Types"
          name="logTypes"
          items={LOG_TYPES}
          inputProps={{ placeholder: 'The types of logs that are collected' }}
          aria-required
          mb={6}
        />
        <AbstractButton
          color="blue300"
          onClick={() => showAdvancedConfig(!isAdvancedConfigVisible)}
          my={6}
          py={3}
        >
          {isAdvancedConfigVisible ? 'Hide advanced configuration' : 'Show advanced configuration'}
        </AbstractButton>
        {isAdvancedConfigVisible && (
          <React.Fragment>
            <Field
              name="s3Prefix"
              as={FormikTextInput}
              label="S3 Prefix Filter"
              aria-required
              placeholder="Limit logs to objects that start with matching characters"
              mb={6}
            />
            <Field
              name="kmsKey"
              as={FormikTextInput}
              label="KMS Key"
              aria-required
              placeholder="For encrypted logs, add the KMS ARN for decryption"
            />
          </React.Fragment>
        )}
      </ErrorBoundary>
    </Box>
  );
};

export default SourceConfigurationPanel;
