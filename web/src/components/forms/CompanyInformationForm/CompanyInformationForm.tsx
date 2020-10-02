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

import * as React from 'react';
import { Field, Form, Formik } from 'formik';
import { Box, Flex, Heading } from 'pouncejs';
import * as Yup from 'yup';
import SubmitButton from 'Components/buttons/SubmitButton';
import FormikTextInput from 'Components/fields/TextInput';
import { AnalyticsConsentSection } from 'Components/forms/AnalyticsConsentForm';

interface CompanyInformationFormValues {
  displayName: string;
  email: string;
  errorReportingConsent: boolean;
  analyticsConsent: boolean;
}

interface CompanyInformationFormProps {
  initialValues: CompanyInformationFormValues;
  onSubmit: (values: CompanyInformationFormValues) => Promise<any>;
}

const validationSchema = Yup.object({
  displayName: Yup.string().required(),
  email: Yup.string().email().required(),
  errorReportingConsent: Yup.boolean().required(),
  analyticsConsent: Yup.boolean().required(),
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
      <Form>
        <Box as="section" mb={6}>
          <Heading as="h2" size="x-small" mb={6}>
            Company Information
          </Heading>
          <Flex direction="column" spacing={4}>
            <Field
              as={FormikTextInput}
              name="displayName"
              label="Company Name"
              placeholder="The name of the company"
              required
            />
            <Field
              as={FormikTextInput}
              name="email"
              label="Email"
              placeholder="The company's email"
              required
            />
          </Flex>
        </Box>
        <Box as="section" mb={6}>
          <Heading as="h2" size="x-small" mb={4}>
            Preferences
          </Heading>
          <AnalyticsConsentSection showErrorConsent showProductAnalyticsConsent />
        </Box>
        <SubmitButton fullWidth>Save</SubmitButton>
      </Form>
    </Formik>
  );
};

export default CompanyInformationForm;
