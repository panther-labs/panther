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
import { AddDestinationConfigInput } from 'Generated/schema';
import BaseDestinationForm, {
  BaseDestinationFormValues,
  defaultValidationSchema,
} from 'Components/forms/BaseDestinationForm';

type GithubFieldValues = Pick<AddDestinationConfigInput, 'github'>;

interface GithubDestinationFormProps {
  initialValues: BaseDestinationFormValues<GithubFieldValues>;
  onSubmit: (values: BaseDestinationFormValues<GithubFieldValues>) => void;
}

const baseGithubShapeObject = {
  repoName: Yup.string().required(),
};

const githubFieldsValidationSchema = Yup.object().shape({
  outputConfig: Yup.object().shape({
    github: Yup.object().shape({ ...baseGithubShapeObject, token: Yup.string().required() }),
  }),
});

const editGithubFieldsValidationSchema = Yup.object().shape({
  outputConfig: Yup.object().shape({
    github: Yup.object().shape(baseGithubShapeObject),
  }),
});

const GithubDestinationForm: React.FC<GithubDestinationFormProps> = ({
  onSubmit,
  initialValues,
}) => {
  const existing = initialValues.displayName.length;
  const validationSchema = existing
    ? defaultValidationSchema.concat(editGithubFieldsValidationSchema)
    : defaultValidationSchema.concat(githubFieldsValidationSchema);

  return (
    <BaseDestinationForm<GithubFieldValues>
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={onSubmit}
    >
      <Field
        as={FormikTextInput}
        name="outputConfig.github.repoName"
        label="Repository name"
        placeholder="What's the name of your Github repository?"
        mb={6}
        aria-required
      />
      <Field
        as={FormikTextInput}
        type="password"
        disabled={existing}
        name="outputConfig.github.token"
        label="Token"
        placeholder="What's your Github API token?"
        mb={6}
        aria-required
        autoComplete="new-password"
      />
    </BaseDestinationForm>
  );
};

export default GithubDestinationForm;
