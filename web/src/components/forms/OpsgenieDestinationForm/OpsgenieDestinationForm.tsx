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

type OpsgenieFieldValues = Pick<DestinationConfigInput, 'opsgenie'>;

interface OpsgenieDestinationFormProps {
  initialValues: BaseDestinationFormValues<OpsgenieFieldValues>;
  onSubmit: (values: BaseDestinationFormValues<OpsgenieFieldValues>) => void;
}

const OpsgenieDestinationForm: React.FC<OpsgenieDestinationFormProps> = ({
  onSubmit,
  initialValues,
}) => {
  const existing = initialValues.outputId;

  const opsgenieFieldsValidationSchema = Yup.object().shape({
    outputConfig: Yup.object().shape({
      opsgenie: Yup.object().shape({
        apiKey: existing ? Yup.string() : Yup.string().required(),
      }),
    }),
  });

  const mergedValidationSchema = defaultValidationSchema.concat(opsgenieFieldsValidationSchema);

  return (
    <BaseDestinationForm<OpsgenieFieldValues>
      initialValues={initialValues}
      validationSchema={mergedValidationSchema}
      onSubmit={onSubmit}
    >
      <Field
        as={FormikTextInput}
        type="password"
        name="outputConfig.opsgenie.apiKey"
        label="Opsgenie API key"
        placeholder={
          existing ? '<hidden information>' : "What's your organization's Opsgenie API key?"
        }
        mb={6}
        aria-required={!existing}
        autoComplete="new-password"
      />
    </BaseDestinationForm>
  );
};

export default OpsgenieDestinationForm;
