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
import FormikCheckbox from 'Components/fields/checkbox';
import { Box, Flex, InputElementLabel, Text } from 'pouncejs';

const ErrorReportingSection: React.FC = () => {
  return (
    <Flex alignItems="flex-start" mb={10}>
      <Field as={FormikCheckbox} name="errorReportingConsent" id="errorReportingConsent" />
      <Box ml={2}>
        <InputElementLabel htmlFor="errorReportingConsent">
          Report web application errors
        </InputElementLabel>
        <Text color="grey300" size="medium">
          Crashes and runtime exceptions will be <b>anonymously</b> reported, in an effort to make
          the Panther team aware of the related issues
        </Text>
      </Box>
    </Flex>
  );
};

export default ErrorReportingSection;
