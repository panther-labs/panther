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

import { Box, Flex, Heading, InputElementLabel, Text } from 'pouncejs';
import ErrorBoundary from 'Components/ErrorBoundary';
import { Field, useFormikContext } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import React from 'react';
import FormikCheckbox from 'Components/fields/Checkbox';
import { PANTHER_SCHEMA_DOCS_LINK } from 'Source/constants';
import { ComplianceSourceWizardValues } from 'Components/wizards/ComplianceSourceWizard/ComplianceSourceWizard';

const SourceConfigurationPanel: React.FC = () => {
  const { initialValues } = useFormikContext<ComplianceSourceWizardValues>();

  return (
    <Box width={460} m="auto">
      <Heading size="medium" m="auto" mb={2} color="grey400">
        {initialValues.integrationId ? 'Update source' : 'First things first'}
      </Heading>
      <Text size="large" color="grey200" mb={10} as="p">
        {initialValues.integrationId
          ? 'Feel free to make any changes to your Cloud Security source'
          : "Let's configure your Cloud Security Source"}
      </Text>
      <ErrorBoundary>
        <Field
          name="integrationLabel"
          as={FormikTextInput}
          label="Name"
          placeholder="A nickname for the AWS account you're onboarding"
          aria-required
          mb={6}
        />
        <Field
          name="awsAccountId"
          as={FormikTextInput}
          label="AWS Account ID"
          placeholder="Your 12-digit AWS Account ID"
          aria-required
          disabled={!!initialValues.integrationId}
          mb={6}
        />
        <Box ml={-2}>
          <Flex align="flex-start" mb={6}>
            <Field as={FormikCheckbox} name="cweEnabled" id="cweEnabled" />
            <Box ml={2}>
              <InputElementLabel htmlFor="cweEnabled">
                Real-Time AWS Resource Scans
              </InputElementLabel>
              <Text color="grey300" size="medium" as="p">
                Configure Panther to monitor all AWS resource changes in real-time through
                CloudWatch Events.{' '}
                <a
                  target="_blank"
                  rel="noopener noreferrer"
                  href={`${PANTHER_SCHEMA_DOCS_LINK}/amazon-web-services/aws-setup/real-time-events`}
                >
                  Read more
                </a>
              </Text>
            </Box>
          </Flex>
          <Flex align="flex-start" mb={6}>
            <Field as={FormikCheckbox} name="remediationEnabled" id="remediationEnabled" />
            <Box ml={2}>
              <InputElementLabel htmlFor="remediationEnabled">
                AWS Automatic Remediations
              </InputElementLabel>
              <Text color="grey300" size="medium" as="p">
                Allow Panther to fix misconfigured infrastructure as soon as it is detected.{' '}
                <a
                  target="_blank"
                  rel="noopener noreferrer"
                  href={`${PANTHER_SCHEMA_DOCS_LINK}/amazon-web-services/aws-setup/automatic-remediation`}
                >
                  Read more
                </a>
              </Text>
            </Box>
          </Flex>
        </Box>
      </ErrorBoundary>
    </Box>
  );
};

export default SourceConfigurationPanel;
