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
import { FastField, Field, useFormikContext } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import React from 'react';
import FormikSwitch from 'Components/fields/Switch';
import logo from 'Assets/aws-minimal-logo.svg';
import { AWS_REGIONS, REMEDIATION_DOC_URL, RESOURCE_TYPES } from 'Source/constants';
import { ComplianceSourceWizardValues } from 'Components/wizards/ComplianceSourceWizard/ComplianceSourceWizard';
import { WizardPanel } from 'Components/Wizard';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';

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
        <Flex direction="column" spacing={6} my={4}>
          <Flex as="fieldset" spacing={8}>
            <FormHelperText id="cweEnabled-description">
              Configure Panther to monitor all AWS resource changes in real-time through CloudWatch
              Events.
            </FormHelperText>
            <Field
              as={FormikSwitch}
              aria-label="Real-Time AWS Resource Scans"
              name="cweEnabled"
              aria-describedby="cweEnabled-description"
            />
          </Flex>
          <Flex as="fieldset" spacing={8}>
            <FormHelperText id="remediationEnabled-description">
              Allow Panther to fix misconfigured infrastructure as soon as it is detected.{' '}
              <Link external href={REMEDIATION_DOC_URL}>
                Read more
              </Link>
            </FormHelperText>
            <Field
              as={FormikSwitch}
              aria-label="AWS Automatic Remediations"
              name="remediationEnabled"
              aria-describedby="remediationEnabled-description"
            />
          </Flex>
          <Box as="fieldset">
            <FastField
              as={FormikMultiCombobox}
              searchable
              label="Exclude AWS Regions"
              name="regionIgnoreList"
              items={AWS_REGIONS}
              aria-describedby="exclude-aws-regions-description"
            />
            <FormHelperText id="exclude-aws-regions-description" mt={2}>
              Disable Cloud Security Scanning for certain AWS regions
            </FormHelperText>
          </Box>
          <Box as="fieldset">
            <FastField
              as={FormikMultiCombobox}
              searchable
              label="Exclude Resource Types"
              name="resourceTypeIgnoreList"
              items={RESOURCE_TYPES}
              aria-describedby="exclude-resourceTypes-description"
            />
            <FormHelperText id="exclude-resourceTypes-description" mt={2}>
              Disable Cloud Security Scanning for certain Resource types
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
