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

import { Box, Flex, IconButton, useSnackbar } from 'pouncejs';
import ErrorBoundary from 'Components/ErrorBoundary';
import { Field, FieldArray, useFormikContext } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import React from 'react';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import { WizardPanel } from 'Components/Wizard';
import logo from 'Assets/s3-minimal-logo.svg';
import { useListAvailableLogTypes } from 'Source/graphql/queries';
import { S3LogSourceWizardValues } from '../S3LogSourceWizard';

const S3SourceConfigurationPanel: React.FC = () => {
  const { initialValues, values, dirty, isValid } = useFormikContext<S3LogSourceWizardValues>();
  const { pushSnackbar } = useSnackbar();
  const { data } = useListAvailableLogTypes({
    onError: () => pushSnackbar({ title: "Couldn't fetch your available log types" }),
  });

  const shouldSkipCFNUpload = React.useMemo(() => {
    return (
      /*
       * If users dont change any of AWS accountId, stackName or Integration label
       * then users dont really need to update their stack or template, so we can skip the next step
       * or proceed to validation.
       * This will apply only to editing since creation requires users to change those field to proceed
       */
      initialValues.integrationLabel === values.integrationLabel &&
      initialValues.s3Bucket === values.s3Bucket
    );
  }, [initialValues, values]);

  // The filtering here is used to prevent users from adding the same log type with different prefixes
  const availableLogTypes = React.useMemo(() => {
    return data?.listAvailableLogTypes.logTypes ?? [];
  }, [data]);

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
              name="kmsKey"
              as={FormikTextInput}
              label="KMS Key"
              placeholder="For encrypted logs, add the KMS ARN for decryption"
            />
          </Flex>
          <Flex direction="column" spacing={4} pt={6}>
            <FieldArray
              name="s3PrefixLogTypes"
              render={arrayHelpers => {
                return values.s3PrefixLogTypes.map((_, index, array) => {
                  return (
                    <Flex
                      key={index}
                      p={4}
                      position="relative"
                      backgroundColor="navyblue-500"
                      spacing={4}
                      direction="column"
                    >
                      <Flex
                        position="absolute"
                        left="100%"
                        top={0}
                        bottom={0}
                        align="center"
                        my={0}
                        spacing={2}
                        ml={2}
                      >
                        {array.length > 1 && (
                          <IconButton
                            size="small"
                            icon="close-outline"
                            variantColor="navyblue"
                            aria-label={`Remove prefix ${index}`}
                            onClick={() => arrayHelpers.remove(index)}
                          />
                        )}
                        {index + 1 === array.length && (
                          <IconButton
                            size="small"
                            icon="add"
                            variantColor="navyblue"
                            aria-label="Add prefix"
                            onClick={() =>
                              arrayHelpers.insert(index + 1, { prefix: '', logTypes: [] })
                            }
                          />
                        )}
                      </Flex>
                      <Field
                        name={`s3PrefixLogTypes.${index}.prefix`}
                        label="S3 Prefix Filter"
                        placeholder="Limit logs to objects that start with matching characters"
                        as={FormikTextInput}
                      />
                      <Field
                        as={FormikMultiCombobox}
                        searchable
                        label="Log Types"
                        required
                        name={`s3PrefixLogTypes.${index}.logTypes`}
                        items={availableLogTypes}
                        placeholder="The types of logs that are collected"
                      />
                    </Flex>
                  );
                });
              }}
            />
          </Flex>
        </ErrorBoundary>
      </Box>
      <WizardPanel.Actions>
        {shouldSkipCFNUpload ? (
          <WizardPanel.ActionGoToStep disabled={!dirty || !isValid} stepIndex={2} />
        ) : (
          <WizardPanel.ActionNext disabled={!dirty || !isValid}>Continue</WizardPanel.ActionNext>
        )}
      </WizardPanel.Actions>
    </WizardPanel>
  );
};

export default S3SourceConfigurationPanel;
