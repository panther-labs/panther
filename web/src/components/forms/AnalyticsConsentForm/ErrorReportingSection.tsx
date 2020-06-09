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
import FormikCheckbox from 'Components/fields/Checkbox';
import { Box, FormHelperText, Link } from 'pouncejs';
import { PANTHER_SCHEMA_DOCS_LINK } from 'Source/constants';

const ErrorReportingSection: React.FC = () => {
  return (
    <Box mb={10}>
      <Field
        as={FormikCheckbox}
        name="errorReportingConsent"
        label="Report Web Application Errors"
        aria-describedby="error-reporting-section-helper"
      />
      <FormHelperText ml={2} id="error-reporting-section-helper">
        Crashes and runtime exceptions.
        <Link
          external
          textDecoration="underline"
          ml={1}
          href={`${PANTHER_SCHEMA_DOCS_LINK}/security-privacy#privacy`}
        >
          Read more
        </Link>
      </FormHelperText>
    </Box>
  );
};

export default ErrorReportingSection;
