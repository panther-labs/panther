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
import { Field, Formik } from 'formik';
import FormikTextInput from 'Components/fields/text-input';
import SubmitButton from 'Components/submit-button';
import * as Yup from 'yup';

export interface UpdateSourceFormValues {
  integrationLabel: string;
}

export interface UpdateSourceFormProps {
  initialValues: UpdateSourceFormValues;
  onSubmit: (values: UpdateSourceFormValues) => Promise<any> | void;
}

const validationSchema = Yup.object().shape({
  integrationLabel: Yup.string().required(),
});

const UpdateSourceForm: React.FC<UpdateSourceFormProps> = ({ onSubmit, initialValues }) => {
  return (
    <Formik<UpdateSourceFormValues>
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={onSubmit}
    >
      {({ handleSubmit, isValid, dirty, isSubmitting }) => (
        <form onSubmit={handleSubmit}>
          <Field
            name="integrationLabel"
            as={FormikTextInput}
            label="Label"
            placeholder="A nickname for this log source"
            aria-required
            mb={6}
          />
          <SubmitButton
            width={1}
            disabled={isSubmitting || !isValid || !dirty}
            submitting={isSubmitting}
          >
            Update
          </SubmitButton>
        </form>
      )}
    </Formik>
  );
};

export default UpdateSourceForm;
