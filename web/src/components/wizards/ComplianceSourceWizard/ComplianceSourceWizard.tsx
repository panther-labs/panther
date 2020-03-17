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
import { AWS_ACCOUNT_ID_REGEX } from 'Source/constants';
import { Formik } from 'formik';
import * as Yup from 'yup';
import { Wizard, WizardPanelWrapper } from 'Components/Wizard';
import { FetchResult } from '@apollo/client';
import { Mutation } from 'Generated/schema';
import StackDeploymentPanel from './StackDeploymentPanel';
import SuccessPanel from './SuccessPanel';
import SourceConfigurationPanel from './SourceConfigurationPanel';

interface ComplianceSourceWizardProps {
  initialValues: ComplianceSourceWizardValues;
  onSubmit: (
    values: ComplianceSourceWizardValues
  ) => Promise<
    FetchResult<Partial<Pick<Mutation, 'addComplianceIntegration' | 'updateComplianceIntegration'>>>
  >;
  externalErrorMessage?: string;
}

export interface ComplianceSourceWizardValues {
  integrationId?: string;
  awsAccountId: string;
  integrationLabel: string;
  cweEnabled: boolean;
  remediationEnabled: boolean;
}

const validationSchema = Yup.object().shape<ComplianceSourceWizardValues>({
  integrationLabel: Yup.string().required(),
  awsAccountId: Yup.string()
    .matches(AWS_ACCOUNT_ID_REGEX, 'Must be a valid AWS Account ID')
    .required(),
  cweEnabled: Yup.boolean().required(),
  remediationEnabled: Yup.boolean().required(),
});

const initialStatus = { cfnTemplateDownloaded: false };

const ComplianceSourceWizard: React.FC<ComplianceSourceWizardProps> = ({
  initialValues,
  onSubmit,
  externalErrorMessage,
}) => {
  return (
    <Formik<ComplianceSourceWizardValues>
      enableReinitialize
      initialValues={initialValues}
      initialStatus={initialStatus}
      validationSchema={validationSchema}
      onSubmit={onSubmit}
    >
      {({ isValid, dirty, handleSubmit, status }) => (
        <form onSubmit={handleSubmit}>
          <Wizard>
            <Wizard.Step title="Configure Source" icon="settings">
              <WizardPanelWrapper>
                <WizardPanelWrapper.Content>
                  <SourceConfigurationPanel />
                </WizardPanelWrapper.Content>
                <WizardPanelWrapper.Actions>
                  <WizardPanelWrapper.ActionNext disabled={!dirty && isValid} />
                </WizardPanelWrapper.Actions>
              </WizardPanelWrapper>
            </Wizard.Step>
            <Wizard.Step title="Deploy Stack" icon="upload">
              <WizardPanelWrapper>
                <WizardPanelWrapper.Content>
                  <StackDeploymentPanel />
                </WizardPanelWrapper.Content>
                <WizardPanelWrapper.Actions>
                  <WizardPanelWrapper.ActionPrev />
                  <WizardPanelWrapper.ActionNext disabled={!status.cfnTemplateDownloaded} />
                </WizardPanelWrapper.Actions>
              </WizardPanelWrapper>
            </Wizard.Step>
            <Wizard.Step title="Done!" icon="check">
              <WizardPanelWrapper>
                <WizardPanelWrapper.Content>
                  <SuccessPanel errorMessage={externalErrorMessage} />
                </WizardPanelWrapper.Content>
                <WizardPanelWrapper.Actions>
                  <WizardPanelWrapper.ActionPrev />
                </WizardPanelWrapper.Actions>
              </WizardPanelWrapper>
            </Wizard.Step>
          </Wizard>
        </form>
      )}
    </Formik>
  );
};

export default ComplianceSourceWizard;
