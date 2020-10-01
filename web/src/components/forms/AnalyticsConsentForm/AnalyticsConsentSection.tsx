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
import { Box, FormHelperText, Link } from 'pouncejs';
import { PRIVACY_DOC_URL } from 'Source/constants';
import FormikSwitch from 'Components/fields/Switch';

const AnalyticsConsentSection: React.FC = () => {
  return (
    <Box as="fieldset">
      <Field
        as={FormikSwitch}
        name="errorReportingConsent"
        label="Report Web Application Errors"
        aria-describedby="error-reporting-section-helper"
      />
      <Box mt={4}>
        <Field
          mt={4}
          as={FormikSwitch}
          name="analyticsConsent"
          label="Report Product Analytics"
          aria-describedby="product-reporting-section-helper"
        />
        <FormHelperText mt={4} id="error-reporting-section-helper">
          Send anonymized runtime exceptions & product analytics <br /> to improve Panther{"'"}s
          reliability.
          <Link external textDecoration="underline" ml={1} href={PRIVACY_DOC_URL}>
            Read more
          </Link>
        </FormHelperText>
      </Box>
    </Box>
  );
};

export default AnalyticsConsentSection;
