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

import { Box, FormHelperText, Heading, Link, Text } from 'pouncejs';
import ErrorBoundary from 'Components/ErrorBoundary';
import { Field, useFormikContext } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import React from 'react';
import FormikCheckbox from 'Components/fields/Checkbox';
import { CLOUD_SECURITY_REAL_TIME_DOC_URL, REMEDIATION_DOC_URL } from 'Source/constants';
import { ComplianceSourceWizardValues } from 'Components/wizards/ComplianceSourceWizard/ComplianceSourceWizard';

const SourceConfigurationPanel: React.FC = () => {
  const { initialValues } = useFormikContext<ComplianceSourceWizardValues>();

  return (
    <Box width={460} m="auto">
      <Heading as="h2" m="auto" mb={2}>
        {initialValues.integrationId ? 'Update source' : 'First things first'}
      </Heading>
      <Text color="gray-300" mb={10}>
        {initialValues.integrationId
          ? 'Feel free to make any changes to your Cloud Security source'
          : "Let's configure your Cloud Security Source"}
      </Text>
      <ErrorBoundary>
        <Box mb={4}>
          <Field
            name="integrationLabel"
            as={FormikTextInput}
            label="Name"
            placeholder="A nickname for the AWS account you're onboarding"
            required
          />
        </Box>
        <Box mb={8}>
          <Field
            name="awsAccountId"
            as={FormikTextInput}
            label="AWS Account ID"
            placeholder="Your 12-digit AWS Account ID"
            required
            disabled={!!initialValues.integrationId}
          />
        </Box>
        <Box ml={-2}>
          <Box as="fieldset" mb={8}>
            <Field
              as={FormikCheckbox}
              name="cweEnabled"
              aria-describedby="cweEnabled-description"
              label="Real-Time AWS Resource Scans"
            />
            <FormHelperText id="cweEnabled-description" ml={2}>
              Configure Panther to monitor all AWS resource changes in real-time through CloudWatch
              Events.{' '}
              <Link external href={CLOUD_SECURITY_REAL_TIME_DOC_URL}>
                Read more
              </Link>
            </FormHelperText>
          </Box>
          <Box as="fieldset" mb={8}>
            <Field
              as={FormikCheckbox}
              name="remediationEnabled"
              aria-describedby="remediationEnabled-description"
              label="AWS Automatic Remediations"
            />
            <FormHelperText id="remediationEnabled-description" ml={2}>
              Allow Panther to fix misconfigured infrastructure as soon as it is detected.
              <br />
              <Link external href={REMEDIATION_DOC_URL}>
                Read more
              </Link>
            </FormHelperText>
          </Box>
        </Box>
      </ErrorBoundary>
    </Box>
  );
};

export default SourceConfigurationPanel;
