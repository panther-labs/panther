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
import SensitiveTextInput from 'Components/fields/SensitiveTextInput';
import { DestinationConfigInput } from 'Generated/schema';
import BaseDestinationForm, {
  BaseDestinationFormValues,
  defaultValidationSchema,
} from 'Components/forms/BaseDestinationForm';
import { SimpleGrid } from 'pouncejs';

type PagerDutyFieldValues = Pick<DestinationConfigInput, 'pagerDuty'>;

interface PagerDutyDestinationFormProps {
  initialValues: BaseDestinationFormValues<PagerDutyFieldValues>;
  onSubmit: (values: BaseDestinationFormValues<PagerDutyFieldValues>) => void;
}

const PagerDutyDestinationForm: React.FC<PagerDutyDestinationFormProps> = ({
  onSubmit,
  initialValues,
}) => {
  const existing = initialValues.outputId;
  const pagerDutyKey = Yup.string().length(32, 'Must be exactly 32 characters');
  const pagerDutyFieldsValidationSchema = Yup.object().shape({
    outputConfig: Yup.object().shape({
      pagerDuty: Yup.object().shape({
        integrationKey: existing ? pagerDutyKey : pagerDutyKey.required(),
      }),
    }),
  });

  const mergedValidationSchema = defaultValidationSchema.concat(pagerDutyFieldsValidationSchema);

  return (
    <BaseDestinationForm<PagerDutyFieldValues>
      initialValues={initialValues}
      validationSchema={mergedValidationSchema}
      onSubmit={onSubmit}
    >
      <SimpleGrid gap={5} columns={2}>
        <Field
          name="displayName"
          as={FormikTextInput}
          label="* Display Name"
          placeholder="How should we name this?"
          required
        />
        <Field
          as={SensitiveTextInput}
          shouldMask={!!existing}
          name="outputConfig.pagerDuty.integrationKey"
          label="Integration Key"
          placeholder="What's your PagerDuty Integration Key?"
          required={!existing}
          autoComplete="new-password"
        />
      </SimpleGrid>
    </BaseDestinationForm>
  );
};

export default PagerDutyDestinationForm;
