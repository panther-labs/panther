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
import { Field } from 'formik';
import FormikCheckbox from 'Components/fields/Checkbox';
import { Box, Flex, InputElementLabel, Text } from 'pouncejs';
import { PANTHER_SCHEMA_DOCS_LINK } from 'Source/constants';

const ErrorReportingSection: React.FC = () => {
  return (
    <Flex alignItems="flex-start" mb={10}>
      <Field as={FormikCheckbox} name="errorReportingConsent" id="errorReportingConsent" />
      <Box ml={2}>
        <InputElementLabel htmlFor="errorReportingConsent">
          Report Web Application Errors
        </InputElementLabel>
        <Flex>
          <Text color="grey300" size="medium">
            Crashes and runtime exceptions.
          </Text>
          &nbsp;
          <Text
            color="grey300"
            size="medium"
            is="a"
            href={`${PANTHER_SCHEMA_DOCS_LINK}/security-privacy#privacy`}
            rel="noopener noreferrer"
          >
            Read more
          </Text>
        </Flex>
      </Box>
    </Flex>
  );
};

export default ErrorReportingSection;
