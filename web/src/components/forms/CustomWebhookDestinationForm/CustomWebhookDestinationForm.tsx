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

type CustomWebhookFieldValues = Pick<AddDestinationConfigInput, 'customWebhook'>;

interface CustomWebhookDestinationFormProps {
  initialValues: BaseDestinationFormValues<CustomWebhookFieldValues>;
  onSubmit: (values: BaseDestinationFormValues<CustomWebhookFieldValues>) => void;
}

const customWebhookFieldsValidationSchema = Yup.object().shape({
  outputConfig: Yup.object().shape({
    customWebhook: Yup.object().shape({
      webhookURL: Yup.string().url('Must be a valid webhook URL').required(),
    }),
  }),
});

// We merge the two schemas together: the one deriving from the common fields, plus the custom
// ones that change for each destination.
// https://github.com/jquense/yup/issues/522
const mergedValidationSchema = defaultValidationSchema.concat(customWebhookFieldsValidationSchema);

const CustomWebhookDestinationForm: React.FC<CustomWebhookDestinationFormProps> = ({
  onSubmit,
  initialValues,
}) => {
  const existing = initialValues.displayName.length;
  const validationSchema = existing ? defaultValidationSchema : mergedValidationSchema;
  return (
    <BaseDestinationForm<CustomWebhookFieldValues>
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={onSubmit}
    >
      <Field
        as={FormikTextInput}
        disabled={existing}
        type="password"
        name="outputConfig.customWebhook.webhookURL"
        label="Custom Webhook URL"
        placeholder="Where should we send a push notification to?"
        mb={6}
        aria-required
      />
    </BaseDestinationForm>
  );
};

export default CustomWebhookDestinationForm;
