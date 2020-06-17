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
import { isNumber } from 'Helpers/utils';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import { Text } from 'pouncejs';

type AsanaFieldValues = Pick<AddDestinationConfigInput, 'asana'>;

interface AsanaDestinationFormProps {
  initialValues: BaseDestinationFormValues<AsanaFieldValues>;
  onSubmit: (values: BaseDestinationFormValues<AsanaFieldValues>) => void;
}

const baseAsanaShapeObject = {
  projectGids: Yup.array().of(Yup.number()).required(),
};

const asanaFieldsValidationSchema = Yup.object().shape({
  outputConfig: Yup.object().shape({
    asana: Yup.object().shape({
      ...baseAsanaShapeObject,
      personalAccessToken: Yup.string().required(),
    }),
  }),
});

const editAsanaFieldsValidationSchema = Yup.object().shape({
  outputConfig: Yup.object().shape({
    asana: Yup.object().shape(baseAsanaShapeObject),
  }),
});

const AsanaDestinationForm: React.FC<AsanaDestinationFormProps> = ({ onSubmit, initialValues }) => {
  const existing = initialValues.outputId;
  const validationSchema = existing
    ? defaultValidationSchema.concat(editAsanaFieldsValidationSchema)
    : defaultValidationSchema.concat(asanaFieldsValidationSchema);

  return (
    <BaseDestinationForm<AsanaFieldValues>
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={onSubmit}
    >
      <Field
        as={FormikTextInput}
        type="password"
        disabled={existing}
        name="outputConfig.asana.personalAccessToken"
        label="Access Token"
        placeholder="Your personal Asana access token"
        mb={6}
        aria-required
      />
      <Field
        name="outputConfig.asana.projectGids"
        as={FormikMultiCombobox}
        label="Project GIDs"
        aria-required
        allowAdditions
        validateAddition={isNumber}
        searchable
        items={[]}
        inputProps={{
          placeholder: 'The GIDs of the projects that will receive the task',
        }}
      />
      <Text size="small" color="grey200" mt={2}>
        Add by pressing the {'<'}Enter{'>'} key
      </Text>
    </BaseDestinationForm>
  );
};

export default AsanaDestinationForm;
