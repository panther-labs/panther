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

import * as React from 'react';
import { Field, Formik } from 'formik';
import { Box, Heading } from 'pouncejs';
import * as Yup from 'yup';
import SubmitButton from 'Components/SubmitButton/SubmitButton';
import FormikTextInput from 'Components/fields/text-input';
import ErrorReportingSection from 'Components/forms/analytics-consent-form/error-reporting-section';

interface CompanyInformationFormValues {
  displayName: string;
  email: string;
  errorReportingConsent: boolean;
}

interface CompanyInformationFormProps {
  initialValues: CompanyInformationFormValues;
  onSubmit: (values: CompanyInformationFormValues) => Promise<any>;
}

const validationSchema = Yup.object({
  displayName: Yup.string().required(),
  email: Yup.string()
    .email()
    .required(),
  errorReportingConsent: Yup.boolean().required(),
});

export const CompanyInformationForm: React.FC<CompanyInformationFormProps> = ({
  initialValues,
  onSubmit,
}) => {
  return (
    <Formik<CompanyInformationFormValues>
      enableReinitialize
      validationSchema={validationSchema}
      initialValues={initialValues}
      onSubmit={onSubmit}
    >
      {({ handleSubmit, isSubmitting, isValid, dirty }) => (
        <Box>
          <form onSubmit={handleSubmit}>
            <Box mb={50}>
              <Heading size="medium" mb={10} color="grey500">
                Company Information
              </Heading>
              <Field
                as={FormikTextInput}
                name="displayName"
                label="Company Name"
                aria-required
                mb={6}
              />
              <Field as={FormikTextInput} name="email" label="Email" aria-required mb={6} />
            </Box>
            <Box mb={50}>
              <Heading size="medium" mb={6} color="grey500">
                Preferences
              </Heading>
              <ErrorReportingSection />
            </Box>
            <SubmitButton
              width={1}
              disabled={!isValid || isSubmitting || !dirty}
              submitting={isSubmitting}
            >
              Save
            </SubmitButton>
          </form>
        </Box>
      )}
    </Formik>
  );
};

export default CompanyInformationForm;
