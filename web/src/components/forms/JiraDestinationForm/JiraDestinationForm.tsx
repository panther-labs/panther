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
import { Field } from 'formik';
import * as Yup from 'yup';
import FormikTextInput from 'Components/fields/TextInput';
import { DestinationConfigInput } from 'Generated/schema';
import BaseDestinationForm, {
  BaseDestinationFormValues,
  defaultValidationSchema,
} from 'Components/forms/BaseDestinationForm';
import { Box, FormHelperText } from 'pouncejs';

type JiraFieldValues = Pick<DestinationConfigInput, 'jira'>;

interface JiraDestinationFormProps {
  initialValues: BaseDestinationFormValues<JiraFieldValues>;
  onSubmit: (values: BaseDestinationFormValues<JiraFieldValues>) => void;
}

const JiraDestinationForm: React.FC<JiraDestinationFormProps> = ({ onSubmit, initialValues }) => {
  const existing = initialValues.outputId;

  const jiraFieldsValidationSchema = Yup.object().shape({
    outputConfig: Yup.object().shape({
      jira: Yup.object().shape({
        orgDomain: Yup.string().url('Must be a valid Jira domain').required(),
        userName: Yup.string().required(),
        projectKey: Yup.string().required(),
        assigneeId: Yup.string(),
        issueType: Yup.string().required(),
        apiKey: existing ? Yup.string() : Yup.string().required(),
      }),
    }),
  });

  const mergedValidationSchema = defaultValidationSchema.concat(jiraFieldsValidationSchema);

  return (
    <BaseDestinationForm<JiraFieldValues>
      initialValues={initialValues}
      validationSchema={mergedValidationSchema}
      onSubmit={onSubmit}
    >
      <Field
        as={FormikTextInput}
        name="outputConfig.jira.orgDomain"
        label="* Organization Domain"
        placeholder="What's your organization's Jira domain?"
        required
      />
      <Field
        as={FormikTextInput}
        name="outputConfig.jira.projectKey"
        label="* Project Key"
        placeholder="What's your Jira Project key?"
        required
        autoComplete="new-password"
      />
      <Field
        as={FormikTextInput}
        name="outputConfig.jira.userName"
        label="* Email"
        placeholder="What's the email of the reporting user?"
      />
      <Field
        as={FormikTextInput}
        type="password"
        name="outputConfig.jira.apiKey"
        label="* Jira API Key"
        placeholder={
          existing
            ? 'Information is hidden. New values will override the existing ones.'
            : "What's the API key of the related Jira account"
        }
        required={!existing}
        autoComplete="new-password"
      />

      <Field
        as={FormikTextInput}
        name="outputConfig.jira.assigneeId"
        label="Assignee ID"
        placeholder="Who should we assign this to?"
      />
      <Box as="fieldset">
        <Field
          as={FormikTextInput}
          name="outputConfig.jira.issueType"
          label="* Issue Type"
          placeholder="What type of issue you want us to create?"
          required
        />
        <FormHelperText id="issueType-helper" mt={2}>
          Can be Bug, Story, Task or any custom type
        </FormHelperText>
      </Box>
    </BaseDestinationForm>
  );
};

export default JiraDestinationForm;
