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
import { isNumber } from 'Helpers/utils';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import { Box, FormHelperText } from 'pouncejs';

type AsanaFieldValues = Pick<DestinationConfigInput, 'asana'>;

interface AsanaDestinationFormProps {
  initialValues: BaseDestinationFormValues<AsanaFieldValues>;
  onSubmit: (values: BaseDestinationFormValues<AsanaFieldValues>) => void;
}

const AsanaDestinationForm: React.FC<AsanaDestinationFormProps> = ({ onSubmit, initialValues }) => {
  const existing = initialValues.outputId;

  const asanaFieldsValidationSchema = Yup.object().shape({
    outputConfig: Yup.object().shape({
      asana: Yup.object().shape({
        projectGids: Yup.array().of(Yup.number()).required(),
        personalAccessToken: existing ? Yup.string() : Yup.string().required(),
      }),
    }),
  });

  const mergedValidationSchema = defaultValidationSchema.concat(asanaFieldsValidationSchema);

  return (
    <BaseDestinationForm<AsanaFieldValues>
      initialValues={initialValues}
      validationSchema={mergedValidationSchema}
      onSubmit={onSubmit}
    >
      <Field
        as={FormikTextInput}
        type="password"
        name="outputConfig.asana.personalAccessToken"
        label="Access Token"
        placeholder={
          existing
            ? 'Information is hidden. New values will override the existing ones.'
            : 'Your personal Asana access token'
        }
        required={!existing}
      />
      <Box as="fieldset">
        <Field
          name="outputConfig.asana.projectGids"
          as={FormikMultiCombobox}
          label="Project GIDs"
          aria-describedby="projectGids-helper"
          allowAdditions
          validateAddition={isNumber}
          searchable
          items={[]}
          placeholder="The GIDs of the projects that will receive the task"
        />
        <FormHelperText id="projectGids-helper" mt={2}>
          Add by pressing the {'<'}Enter{'>'} key
        </FormHelperText>
      </Box>
    </BaseDestinationForm>
  );
};

export default AsanaDestinationForm;
