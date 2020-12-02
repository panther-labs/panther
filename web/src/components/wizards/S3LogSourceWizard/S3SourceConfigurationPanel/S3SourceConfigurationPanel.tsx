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

import { AbstractButton, Box, Collapse, Flex, useSnackbar } from 'pouncejs';
import ErrorBoundary from 'Components/ErrorBoundary';
import { Field, useFormikContext } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import React from 'react';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import { WizardPanel } from 'Components/Wizard';
import logo from 'Assets/s3-minimal-logo.svg';
import { useListAvailableLogTypes } from 'Source/graphql/queries';
import { S3LogSourceWizardValues } from '../S3LogSourceWizard';

const S3SourceConfigurationPanel: React.FC = () => {
  const { initialValues, values, dirty, isValid } = useFormikContext<S3LogSourceWizardValues>();
  const [isAdvancedConfigVisible, showAdvancedConfig] = React.useState(
    Boolean(values.s3Prefix) || Boolean(values.kmsKey)
  );
  const { pushSnackbar } = useSnackbar();
  const { data } = useListAvailableLogTypes({
    onError: () => pushSnackbar({ title: "Couldn't fetch your available log types" }),
  });

  return (
    <WizardPanel>
      <Box width={500} m="auto">
        <WizardPanel.Heading
          title={initialValues.integrationId ? 'Update your source' : 'Configure your source'}
          subtitle={
            initialValues.integrationId
              ? 'Feel free to make any changes to your log source'
              : 'We need to know where to get your logs from'
          }
          logo={logo}
        />

        <ErrorBoundary>
          <Flex direction="column" spacing={4}>
            <Field
              name="integrationLabel"
              as={FormikTextInput}
              label="Name"
              placeholder="A nickname for this log analysis source"
              required
            />
            <Field
              name="awsAccountId"
              as={FormikTextInput}
              label="AWS Account ID"
              placeholder="The AWS Account ID that the S3 log bucket lives in"
              disabled={!!initialValues.integrationId}
              required
            />
            <Field
              name="s3Bucket"
              as={FormikTextInput}
              label="Bucket Name"
              required
              placeholder="The name of the S3 bucket that holds the logs"
            />
            <Field
              as={FormikMultiCombobox}
              searchable
              label="Log Types"
              name="logTypes"
              items={data?.listAvailableLogTypes.logTypes ?? []}
              placeholder="The types of logs that are collected"
            />
          </Flex>
          <Flex justify="center" mt={6}>
            <AbstractButton
              color="teal-400"
              fontSize="medium"
              onClick={() => showAdvancedConfig(!isAdvancedConfigVisible)}
              p={1}
            >
              {isAdvancedConfigVisible
                ? 'Hide advanced configuration'
                : 'Show advanced configuration'}
            </AbstractButton>
          </Flex>
          <Collapse open={isAdvancedConfigVisible}>
            <Flex direction="column" spacing={4} pt={6}>
              <Field
                name="s3Prefix"
                as={FormikTextInput}
                label="S3 Prefix Filter"
                required
                placeholder="Limit logs to objects that start with matching characters"
              />
              <Field
                name="kmsKey"
                as={FormikTextInput}
                label="KMS Key"
                required
                placeholder="For encrypted logs, add the KMS ARN for decryption"
              />
            </Flex>
          </Collapse>
        </ErrorBoundary>
      </Box>
      <WizardPanel.Actions>
        <WizardPanel.ActionNext disabled={!dirty || !isValid}>
          Continue Setup
        </WizardPanel.ActionNext>
      </WizardPanel.Actions>
    </WizardPanel>
  );
};

export default S3SourceConfigurationPanel;
