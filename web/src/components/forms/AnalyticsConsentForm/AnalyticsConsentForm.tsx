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
import { Form, Formik } from 'formik';
import { Box } from 'pouncejs';
import * as Yup from 'yup';
import SubmitButton from 'Components/buttons/SubmitButton';
import AnalyticsConsentSection from './AnalyticsConsentSection';

interface AnalyticsConsentFormValues {
  errorReportingConsent?: boolean;
  analyticsConsent: boolean;
}

interface AnalyticsConsentFormProps {
  showErrorConsent: boolean;
  showProductAnalyticsConsent: boolean;
  onSubmit: (values: AnalyticsConsentFormValues) => Promise<any>;
}

const initialValues = {
  errorReportingConsent: true,
  analyticsConsent: true,
};

const AnalyticsConsentForm: React.FC<AnalyticsConsentFormProps> = ({
  showErrorConsent,
  showProductAnalyticsConsent,
  onSubmit,
}) => {
  const validationSchema = Yup.object().shape({
    errorReportingConsent: showErrorConsent ? Yup.boolean().required() : null,
    analyticsConsent: showProductAnalyticsConsent ? Yup.boolean().required() : null,
  });
  return (
    <Formik<AnalyticsConsentFormValues>
      initialValues={showErrorConsent ? initialValues : { analyticsConsent: true }}
      validationSchema={validationSchema}
      onSubmit={onSubmit}
    >
      <Form>
        <Box mb={10}>
          <AnalyticsConsentSection
            showErrorConsent={showErrorConsent}
            showProductAnalyticsConsent={showProductAnalyticsConsent}
          />
        </Box>
        <SubmitButton fullWidth allowPristineSubmission>
          Save
        </SubmitButton>
      </Form>
    </Formik>
  );
};

export default AnalyticsConsentForm;
