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
import { webhookValidation } from 'Helpers/utils';

type SlackFieldValues = Pick<DestinationConfigInput, 'slack'>;

interface SlackDestinationFormProps {
  initialValues: BaseDestinationFormValues<SlackFieldValues>;
  onSubmit: (values: BaseDestinationFormValues<SlackFieldValues>) => void;
}

const SlackDestinationForm: React.FC<SlackDestinationFormProps> = ({ onSubmit, initialValues }) => {
  const existing = initialValues.outputId;

  const slackFieldsValidationSchema = Yup.object().shape({
    outputConfig: Yup.object().shape({
      slack: Yup.object().shape({
        webhookURL: existing ? webhookValidation() : webhookValidation().required(),
      }),
    }),
  });

  const mergedValidationSchema = defaultValidationSchema.concat(slackFieldsValidationSchema);

  return (
    <BaseDestinationForm<SlackFieldValues>
      initialValues={initialValues}
      validationSchema={mergedValidationSchema}
      onSubmit={onSubmit}
    >
      <Field
        as={FormikTextInput}
        type="password"
        name="outputConfig.slack.webhookURL"
        label="Slack Webhook URL"
        placeholder={
          existing ? '<hidden information>' : 'Where should we send a push notification to?'
        }
        mb={6}
        aria-required={!existing}
      />
    </BaseDestinationForm>
  );
};

export default SlackDestinationForm;
