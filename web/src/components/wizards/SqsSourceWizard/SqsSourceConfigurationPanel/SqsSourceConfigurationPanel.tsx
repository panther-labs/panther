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
import { Box, Flex, FormHelperText, Heading, Text } from 'pouncejs';
import ErrorBoundary from 'Components/ErrorBoundary';
import { FastField, Field, useFormikContext } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import { LOG_TYPES } from 'Source/constants';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import { pantherConfig } from 'Source/config';
import { SqsLogSourceWizardValues } from '../SqsSourceWizard';

const SqsSourceConfigurationPanel: React.FC = () => {
  const { initialValues } = useFormikContext<SqsLogSourceWizardValues>();

  return (
    <Box width={460} m="auto">
      <Heading as="h2" m="auto" mb={2}>
        {initialValues.integrationId ? 'Update the SQS source' : "Let's start with the basics"}
      </Heading>
      <Text color="gray-300" mb={4}>
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
            label="Allowed AWS Principal ARNs"
            name="allowedPrincipalArns"
            searchable
            allowAdditions
            items={[]}
            placeholder="Enter AWS Principals ARNs"
          />
          <FormHelperText id="aws-principals-arn-helper" ml={3} pb={4}>
            Add the ARN of the AWS Principals that are allowed to send data to the queue i.e.
            arn:aws:iam::{pantherConfig.AWS_ACCOUNT_ID}:root
          </FormHelperText>

          <FastField
            as={FormikMultiCombobox}
            label="Allowed source ARNs"
            name="allowedSourceArns"
            searchable
            allowAdditions
            items={[]}
            placeholder="Enter AWS resources ARNs"
          />
          <FormHelperText id="aws-resources-arn-helper" ml={3}>
            Specify which AWS resources (SNS topics, S3 buckets, etc) are allowed to send data to
            the queue i.e. arn:aws:sns:{pantherConfig.AWS_REGION}:{pantherConfig.AWS_ACCOUNT_ID}
            :my-topic
          </FormHelperText>
        </Flex>
      </ErrorBoundary>
    </Box>
  );
};

export default SqsSourceConfigurationPanel;
