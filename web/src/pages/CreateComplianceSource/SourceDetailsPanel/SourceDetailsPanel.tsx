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

import { Box, Heading, Text } from 'pouncejs';
import ErrorBoundary from 'Components/ErrorBoundary';
import { Field } from 'formik';
import FormikTextInput from 'Components/Fields/TextInput';
import React from 'react';

const SourceDetailsPanel: React.FC = () => {
  return (
    <Box width={460} m="auto">
      <Heading size="medium" m="auto" mb={5} color="grey400">
        Let{"'"}s start with some account information
      </Heading>
      <Text size="large" color="grey200" mb={10}>
        Before we begin, we need to setup a few things in our database
      </Text>
      <ErrorBoundary>
        <Field
          name="awsAccountId"
          as={FormikTextInput}
          label="AWS Account ID"
          placeholder="Your 12-digit AWS Account ID"
          aria-required
          mb={6}
        />
        <Field
          name="integrationLabel"
          as={FormikTextInput}
          label="Label"
          placeholder="A nickname for your account"
          aria-required
          mb={6}
        />
      </ErrorBoundary>
    </Box>
  );
};

export default SourceDetailsPanel;
