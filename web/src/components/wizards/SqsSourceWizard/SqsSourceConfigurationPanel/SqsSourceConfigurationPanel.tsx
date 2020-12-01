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
import { Box, Flex, FormHelperText, useSnackbar } from 'pouncejs';
import ErrorBoundary from 'Components/ErrorBoundary';
import { FastField, Field, useFormikContext } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import { WizardPanel } from 'Components/Wizard';
import { pantherConfig } from 'Source/config';
import logo from 'Assets/sqs-minimal-logo.svg';
import { useListAvailableLogTypes } from 'Source/graphql/queries';
import { SqsLogSourceWizardValues } from '../SqsSourceWizard';

const emptyArray = [];

const SqsSourceConfigurationPanel: React.FC = () => {
  const { initialValues, isValid, dirty } = useFormikContext<SqsLogSourceWizardValues>();
  const { pushSnackbar } = useSnackbar();
  const { data } = useListAvailableLogTypes({
    onError: () => pushSnackbar({ title: "Couldn't fetch your available log types" }),
  });

  return (
    <WizardPanel>
      <Box width={500} m="auto">
        <WizardPanel.Heading
          title={initialValues.integrationId ? 'Update the SQS source' : 'Configure your source'}
          subtitle={
            initialValues.integrationId
              ? 'Feel free to make any changes to your SQS log source'
              : 'We need some information in order to create your queue'
          }
          logo={logo}
        />
        <ErrorBoundary>
          <Flex direction="column" spacing={5}>
            <Field
              name="integrationLabel"
              as={FormikTextInput}
              label="Name"
              placeholder="A nickname for this SQS log source"
              required
            />
            <Field
              as={FormikMultiCombobox}
              searchable
              label="Log Types"
              name="logTypes"
              items={data?.listAvailableLogTypes.logTypes ?? []}
              placeholder="Which log types should we monitor?"
            />
            <Box as="fieldset">
              <FastField
                as={FormikMultiCombobox}
                label="Allowed AWS Principal ARNs"
                name="allowedPrincipalArns"
                searchable
                allowAdditions
                items={emptyArray}
                placeholder="The allowed AWS Principals ARNs (separated with <Enter>)"
              />
              <FormHelperText id="aws-principals-arn-helper" mt={4}>
                <i>
                  The ARN of the AWS Principals that are allowed to send data to the queue,
                  separated with {'<'}Enter{'>'} (i.e. arn:aws:iam::{pantherConfig.AWS_ACCOUNT_ID}
                  :root)
                </i>
              </FormHelperText>
            </Box>
            <Box as="fieldset">
              <FastField
                as={FormikMultiCombobox}
                label="Allowed Source ARNs"
                name="allowedSourceArns"
                searchable
                allowAdditions
                items={emptyArray}
                placeholder="The allowed AWS resources ARNs (separated with <Enter>)"
              />
              <FormHelperText id="aws-resources-arn-helper" mt={4}>
                <i>
                  The AWS resources (SNS topics, S3 buckets, etc) that are allowed to send data to
                  the queue, separated with {'<'}Enter{'>'} (i.e. arn:aws:sns:
                  {pantherConfig.AWS_REGION}:{pantherConfig.AWS_ACCOUNT_ID}
                  :my-topic).
                </i>
              </FormHelperText>
            </Box>
          </Flex>
        </ErrorBoundary>
      </Box>
      <WizardPanel.Actions>
        <WizardPanel.ActionNext disabled={!isValid || !dirty}>
          Continue Setup
        </WizardPanel.ActionNext>
      </WizardPanel.Actions>
    </WizardPanel>
  );
};

export default SqsSourceConfigurationPanel;
