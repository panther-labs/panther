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
import FormikTextInput from 'Components/Fields/text-input';
import { DestinationConfigInput } from 'Generated/schema';
import BaseDestinationForm, {
  BaseDestinationFormValues,
  defaultValidationSchema,
} from 'Components/forms/common/base-destination-form';

type SlackFieldValues = Pick<DestinationConfigInput, 'slack'>;

interface SlackDestinationFormProps {
  initialValues: BaseDestinationFormValues<SlackFieldValues>;
  onSubmit: (values: BaseDestinationFormValues<SlackFieldValues>) => void;
}

const slackFieldsValidationSchema = Yup.object().shape({
  outputConfig: Yup.object().shape({
    slack: Yup.object().shape({
      webhookURL: Yup.string()
        .url('Must be a valid webhook URL')
        .required(),
    }),
  }),
});

// @ts-ignore
// We merge the two schemas together: the one deriving from the common Fields, plus the custom
// ones that change for each destination.
// https://github.com/jquense/yup/issues/522
const mergedValidationSchema = defaultValidationSchema.concat(slackFieldsValidationSchema);

const SlackDestinationForm: React.FC<SlackDestinationFormProps> = ({ onSubmit, initialValues }) => {
  return (
    <BaseDestinationForm<SlackFieldValues>
      initialValues={initialValues}
      validationSchema={mergedValidationSchema}
      onSubmit={onSubmit}
    >
      <Field
        as={FormikTextInput}
        name="outputConfig.slack.webhookURL"
        label="Slack Webhook URL"
        placeholder="Where should we send a push notification to?"
        mb={6}
        aria-required
      />
    </BaseDestinationForm>
  );
};

export default SlackDestinationForm;
