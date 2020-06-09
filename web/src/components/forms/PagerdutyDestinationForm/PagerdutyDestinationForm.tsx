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

type PagerDutyFieldValues = Pick<DestinationConfigInput, 'pagerDuty'>;

interface PagerDutyDestinationFormProps {
  initialValues: BaseDestinationFormValues<PagerDutyFieldValues>;
  onSubmit: (values: BaseDestinationFormValues<PagerDutyFieldValues>) => void;
}

const pagerDutyFieldsValidationSchema = Yup.object().shape({
  outputConfig: Yup.object().shape({
    pagerDuty: Yup.object().shape({
      integrationKey: Yup.string().length(32, 'Must be exactly 32 characters').required(),
    }),
  }),
});

// We merge the two schemas together: the one deriving from the common fields, plus the custom
// ones that change for each destination.
// https://github.com/jquense/yup/issues/522
const mergedValidationSchema = defaultValidationSchema.concat(pagerDutyFieldsValidationSchema);

const PagerDutyDestinationForm: React.FC<PagerDutyDestinationFormProps> = ({
  onSubmit,
  initialValues,
}) => {
  return (
    <BaseDestinationForm<PagerDutyFieldValues>
      initialValues={initialValues}
      validationSchema={mergedValidationSchema}
      onSubmit={onSubmit}
    >
      <Field
        as={FormikTextInput}
        name="outputConfig.pagerDuty.integrationKey"
        label="Integration Key"
        placeholder="What's your PagerDuty Integration Key?"
        mb={6}
        aria-required
        autoComplete="new-password"
      />
    </BaseDestinationForm>
  );
};

export default PagerDutyDestinationForm;
