/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
import FormikTextInput from 'Components/fields/text-input';
import { DestinationConfigInput } from 'Generated/schema';
import { Text } from 'pouncejs';
import BaseDestinationForm, {
  BaseDestinationFormValues,
  defaultValidationSchema,
} from 'Components/forms/common/base-destination-form';

type EmailFieldValues = Pick<DestinationConfigInput, 'email'>;

interface EmailDestinationFormProps {
  initialValues: BaseDestinationFormValues<EmailFieldValues>;
  onSubmit: (values: BaseDestinationFormValues<EmailFieldValues>) => void;
}

const emailFieldsValidationSchema = Yup.object().shape({
  outputConfig: Yup.object().shape({
    email: Yup.object().shape({
      destinationAddress: Yup.string()
        .email('Must be a valid email address')
        .required(),
    }),
  }),
});

// @ts-ignore
// We merge the two schemas together: the one deriving from the common fields, plus the custom
// ones that change for each destination.
// https://github.com/jquense/yup/issues/522
const mergedValidationSchema = defaultValidationSchema.concat(emailFieldsValidationSchema);

const EmailDestinationForm: React.FC<EmailDestinationFormProps> = ({ onSubmit, initialValues }) => {
  return (
    <BaseDestinationForm<EmailFieldValues>
      initialValues={initialValues}
      validationSchema={mergedValidationSchema}
      onSubmit={onSubmit}
    >
      <Field
        as={FormikTextInput}
        name="outputConfig.email.destinationAddress"
        label="Email Address"
        placeholder="Where should we send an email notification to?"
        mb={3}
        aria-required
      />
      <Text size="small" color="grey300" mb={6}>
        * If the email address is not already verified, we will immediately send a verification
        email to it. Until it gets verified, it will not be eligible to receive any alerts.
      </Text>
    </BaseDestinationForm>
  );
};

export default EmailDestinationForm;
