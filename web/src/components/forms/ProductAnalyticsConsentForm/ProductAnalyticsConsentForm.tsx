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
import ProductReportingSection from './ProductReportingSection';

interface ProductAnalyticsConsentFormValues {
  analyticsConsent: boolean;
}

interface AnalyticsConsentFormProps {
  onSubmit: (values: ProductAnalyticsConsentFormValues) => Promise<any>;
}

const validationSchema = Yup.object().shape({
  analyticsConsent: Yup.boolean().required(),
});

const initialValues = {
  analyticsConsent: true,
};

const ProductAnalyticsConsentForm: React.FC<AnalyticsConsentFormProps> = ({ onSubmit }) => {
  return (
    <Formik<ProductAnalyticsConsentFormValues>
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={onSubmit}
    >
      <Form>
        <Box mb={10}>
          <ProductReportingSection />
        </Box>
        <SubmitButton fullWidth allowPristineSubmission>
          Save
        </SubmitButton>
      </Form>
    </Formik>
  );
};

export default ProductAnalyticsConsentForm;
