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
import FormikCombobox from 'Components/fields/ComboBox';
import { DestinationConfigInput, JiraIssueTypesEnum } from 'Generated/schema';
import BaseDestinationForm, {
  BaseDestinationFormValues,
  defaultValidationSchema,
} from 'Components/forms/BaseDestinationForm';

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
        userName: Yup.string(),
        projectKey: Yup.string().required(),
        assigneeId: Yup.string(),
        issueType: Yup.string().test('oneOf', 'Please select a valid value', value =>
          Object.values(JiraIssueTypesEnum).includes(value)
        ),
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
        label="Organization Domain"
        placeholder="What's your organization's Jira domain?"
        mb={6}
        aria-required
      />
      <Field
        as={FormikTextInput}
        name="outputConfig.jira.projectKey"
        label="Project Key"
        placeholder="What's your Jira Project key?"
        mb={6}
        aria-required
        autoComplete="new-password"
      />
      <Field
        as={FormikTextInput}
        name="outputConfig.jira.userName"
        label="Email"
        placeholder="What's the email of the reporting user?"
        mb={6}
      />
      <Field
        as={FormikTextInput}
        type="password"
        name="outputConfig.jira.apiKey"
        label="Jira API Key"
        placeholder={
          existing ? '<hidden information>' : "What's the API key of the related Jira account"
        }
        mb={6}
        aria-required
        autoComplete="new-password"
      />

      <Field
        as={FormikTextInput}
        name="outputConfig.jira.assigneeId"
        label="Assignee ID"
        placeholder="Who should we assign this to?"
        mb={6}
      />
      <Field
        as={FormikCombobox}
        name="outputConfig.jira.issueType"
        label="Issue Type"
        mb={6}
        aria-required
        items={Object.keys(JiraIssueTypesEnum)}
        inputProps={{ placeholder: 'Select a type of issue' }}
      />
    </BaseDestinationForm>
  );
};

export default JiraDestinationForm;
