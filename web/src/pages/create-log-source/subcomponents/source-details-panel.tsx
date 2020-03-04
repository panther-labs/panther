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
import { Box, Heading, Text } from 'pouncejs';
import ErrorBoundary from 'Components/ErrorBoundary';
import { Field } from 'formik';
import FormikTextInput from 'Components/Fields/text-input';
import FormikMultiCombobox from 'Components/Fields/multi-combobox';
import { getArnRegexForService } from 'Helpers/utils';

const SourceDetailsPanel: React.FC = () => {
  return (
    <Box width={460} m="auto">
      <Heading size="medium" m="auto" mb={5} color="grey400">
        Let{"'"}s start with the basics
      </Heading>
      <Text size="large" color="grey200" mb={5}>
        We need to know where to get your logs from
      </Text>
      <ErrorBoundary>
        <Field
          name="integrationLabel"
          as={FormikTextInput}
          label="Label"
          placeholder="A nickname for this log source"
          aria-required
          mb={6}
        />
        <Field
          name="awsAccountId"
          as={FormikTextInput}
          label="Related Account ID"
          placeholder="The AWS Account ID that the S3 log buckets live in"
          aria-required
          items={[]}
          mb={6}
        />
        <Field
          name="s3Buckets"
          as={FormikMultiCombobox}
          label="S3 Buckets"
          aria-required
          allowAdditions
          searchable
          items={[]}
          inputProps={{
            placeholder: 'The S3 bucket names that the logs are stored in',
          }}
        />
        <Text size="small" color="grey200" mt={2} mb={6}>
          Add by pressing the {'<'}Enter{'>'} key
        </Text>
        <Field
          name="kmsKeys"
          as={FormikMultiCombobox}
          label="KMS Keys (Optional)"
          aria-required
          allowAdditions
          validateAddition={str => getArnRegexForService('KMS').test(str)}
          searchable
          items={[]}
          inputProps={{
            placeholder: 'For encrypted logs, add the KMS ARNs for decryption',
          }}
        />
        <Text size="small" color="grey200" mt={2}>
          Add by pressing the {'<'}Enter{'>'} key
        </Text>
      </ErrorBoundary>
    </Box>
  );
};

export default SourceDetailsPanel;
