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
import {
  AWS_ACCOUNT_ID_REGEX,
  LOG_TYPES,
  S3_BUCKET_NAME_REGEX,
  SOURCE_LABEL_REGEX,
} from 'Source/constants';
import { Formik } from 'formik';
import * as Yup from 'yup';
import { Wizard, WizardPanelWrapper } from 'Components/Wizard';
import { FetchResult } from '@apollo/client';
import { getArnRegexForService } from 'Helpers/utils';
import StackDeploymentPanel from './StackDeploymentPanel';
import SuccessPanel from './SuccessPanel';
import SourceConfigurationPanel from './SourceConfigurationPanel';

interface LogSourceWizardProps {
  initialValues: LogSourceWizardValues;
  onSubmit: (values: LogSourceWizardValues) => Promise<FetchResult<any>>;
  externalErrorMessage?: string;
}

export interface LogSourceWizardValues {
  // for updates
  integrationId?: string;
  initialStackName?: string;
  // common for creation + updates
  awsAccountId: string;
  integrationLabel: string;
  s3Bucket: string;
  s3Prefix: string;
  kmsKey: string;
  logTypes: string[];
}

const validationSchema = Yup.object().shape<LogSourceWizardValues>({
  integrationLabel: Yup.string()
    .matches(SOURCE_LABEL_REGEX, 'Can only include alphanumeric characters, dashes and spaces')
    .max(32, 'Must be at most 32 characters')
    .required(),
  awsAccountId: Yup.string()
    .matches(AWS_ACCOUNT_ID_REGEX, 'Must be a valid AWS Account ID')
    .required(),
  s3Bucket: Yup.string()
    .matches(S3_BUCKET_NAME_REGEX, 'Must be valid S3 Bucket name')
    .required(),
  logTypes: Yup.array()
    .of(Yup.string().oneOf((LOG_TYPES as unknown) as string[]))
    .required(),
  s3Prefix: Yup.string(),
  kmsKey: Yup.string().matches(getArnRegexForService('KMS'), 'Must be a valid KMS ARN'),
});

const initialStatus = { cfnTemplateDownloaded: false };

const LogSourceWizard: React.FC<LogSourceWizardProps> = ({
  initialValues,
  onSubmit,
  externalErrorMessage,
}) => {
  return (
    <Formik<LogSourceWizardValues>
      enableReinitialize
      initialValues={initialValues}
      initialStatus={initialStatus}
      validationSchema={validationSchema}
      onSubmit={onSubmit}
    >
      {({ isValid, dirty, handleSubmit, status, setStatus }) => {
        // We want to reset the error message whenever the user goes back to a previous screen.
        // That's why we handle it through status in order to manipulate it internally
        React.useEffect(() => {
          setStatus({ ...status, errorMessage: externalErrorMessage });
        }, [externalErrorMessage]);

        return (
          <form onSubmit={handleSubmit}>
            <Wizard>
              <Wizard.Step title="Configure Logs Source" icon="settings">
                <WizardPanelWrapper>
                  <WizardPanelWrapper.Content>
                    <SourceConfigurationPanel />
                  </WizardPanelWrapper.Content>
                  <WizardPanelWrapper.Actions>
                    <WizardPanelWrapper.ActionNext disabled={!dirty || !isValid} />
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
                    <WizardPanelWrapper.ActionNext />
                  </WizardPanelWrapper.Actions>
                </WizardPanelWrapper>
              </Wizard.Step>
              <Wizard.Step title="Done!" icon="check">
                <WizardPanelWrapper>
                  <WizardPanelWrapper.Content>
                    <SuccessPanel />
                  </WizardPanelWrapper.Content>
                  <WizardPanelWrapper.Actions>
                    <WizardPanelWrapper.ActionPrev />
                  </WizardPanelWrapper.Actions>
                </WizardPanelWrapper>
              </Wizard.Step>
            </Wizard>
          </form>
        );
      }}
    </Formik>
  );
};

export default LogSourceWizard;
