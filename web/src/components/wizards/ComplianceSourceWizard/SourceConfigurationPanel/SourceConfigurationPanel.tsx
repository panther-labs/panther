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

import { Box, Flex, FormHelperText, Link } from 'pouncejs';
import { Field, useFormikContext } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import React from 'react';
import FormikCheckbox from 'Components/fields/Checkbox';
import logo from 'Assets/aws-minimal-logo.svg';
import { REMEDIATION_DOC_URL } from 'Source/constants';
import { ComplianceSourceWizardValues } from 'Components/wizards/ComplianceSourceWizard/ComplianceSourceWizard';
import { WizardPanel } from 'Components/Wizard';

const SourceConfigurationPanel: React.FC = () => {
  const { initialValues, dirty, isValid } = useFormikContext<ComplianceSourceWizardValues>();

  return (
    <WizardPanel>
      <Box width={400} m="auto">
        <WizardPanel.Heading
          title={
            initialValues.integrationId
              ? `Update ${initialValues.integrationLabel}`
              : 'First things first'
          }
          subtitle={
            initialValues.integrationId
              ? 'Feel free to make any changes to you want'
              : 'Let’s configure your Cloud Security Source'
          }
          logo={logo}
        />
        <Flex direction="column" spacing={4}>
          <Field
            name="integrationLabel"
            as={FormikTextInput}
            label="Name"
            placeholder="A nickname for the AWS account you're onboarding"
            required
          />
          <Field
            name="awsAccountId"
            as={FormikTextInput}
            label="AWS Account ID"
            placeholder="Your 12-digit AWS Account ID"
            required
            disabled={!!initialValues.integrationId}
          />
        </Flex>
        <Flex direction="column" spacing={6} my={4} ml={-2}>
          <Box as="fieldset">
            <Field
              as={FormikCheckbox}
              name="cweEnabled"
              aria-describedby="cweEnabled-description"
              label="Real-Time AWS Resource Scans"
            />
            <FormHelperText id="cweEnabled-description" ml={45}>
              Configure Panther to monitor all AWS resource changes in real-time through CloudWatch
              Events.
            </FormHelperText>
          </Box>
          <Box as="fieldset">
            <Field
              as={FormikCheckbox}
              name="remediationEnabled"
              aria-describedby="remediationEnabled-description"
              label="AWS Automatic Remediations"
            />
            <FormHelperText id="remediationEnabled-description" ml={45}>
              Allow Panther to fix misconfigured infrastructure as soon as it is detected.{' '}
              <Link external href={REMEDIATION_DOC_URL}>
                Read more
              </Link>
            </FormHelperText>
          </Box>
        </Flex>
        <WizardPanel.Actions>
          <WizardPanel.ActionNext disabled={!dirty || !isValid}>
            Continue Setup
          </WizardPanel.ActionNext>
        </WizardPanel.Actions>
      </Box>
    </WizardPanel>
  );
};

export default SourceConfigurationPanel;
