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
import { LOG_TYPES } from 'Source/constants';
import { Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FetchResult } from '@apollo/client';
import { Wizard, WizardPanelWrapper } from 'Components/Wizard';
import { yupIntegrationLabelValidation } from 'Helpers/utils';
import SuccessPanel from './SuccessPanel';
import SqsSourceConfigurationPanel from './SqsSourceConfigurationPanel';
import InformationPanel from './InformationPanel';

interface SqsLogSourceWizardProps {
  initialValues: SqsLogSourceWizardValues;
  onSubmit: (values: SqsLogSourceWizardValues) => Promise<FetchResult<any>>;
  externalErrorMessage?: string;
}

export interface SqsLogSourceWizardValues {
  // for updates
  integrationId?: string;
  integrationLabel: string;
  logTypes: string[];
  allowedPrincipalArns: string[];
  allowedSourceArns: string[];
  queueUrl?: string;
}

const validationSchema = Yup.object().shape<SqsLogSourceWizardValues>({
  integrationLabel: yupIntegrationLabelValidation,
  logTypes: Yup.array()
    .of(Yup.string().oneOf((LOG_TYPES as unknown) as string[]))
    .required(),
  allowedPrincipalArns: Yup.array().of(Yup.string()),
  allowedSourceArns: Yup.array().of(Yup.string()),
});

const initialStatus = {};

const SqsSourceWizard: React.FC<SqsLogSourceWizardProps> = ({
  initialValues,
  onSubmit,
  externalErrorMessage,
}) => {
  return (
    <Formik<SqsLogSourceWizardValues>
      enableReinitialize
      initialValues={initialValues}
      initialStatus={initialStatus}
      validationSchema={validationSchema}
      onSubmit={onSubmit}
    >
      {({ values, isValid, dirty, status, setStatus }) => {
        // We want to reset the error message whenever the user goes back to a previous screen.
        // That's why we handle it through status in order to manipulate it internally
        React.useEffect(() => {
          setStatus({
            ...status,
            errorMessage: externalErrorMessage,
          });
        }, [externalErrorMessage]);

        return (
          <Form>
            <Wizard>
              {initialValues.integrationId && (
                <Wizard.Step title="Information">
                  <WizardPanelWrapper>
                    <WizardPanelWrapper.Content>
                      <InformationPanel />
                    </WizardPanelWrapper.Content>
                    <WizardPanelWrapper.Actions>
                      <WizardPanelWrapper.ActionNext />
                    </WizardPanelWrapper.Actions>
                  </WizardPanelWrapper>
                </Wizard.Step>
              )}
              <Wizard.Step title="Configure">
                <WizardPanelWrapper>
                  <WizardPanelWrapper.Content>
                    <SqsSourceConfigurationPanel />
                  </WizardPanelWrapper.Content>
                  <WizardPanelWrapper.Actions>
                    {initialValues.integrationId && <WizardPanelWrapper.ActionPrev />}
                    <WizardPanelWrapper.ActionNext
                      disabled={
                        (!values.logTypes.length && !values.integrationLabel) || !isValid || !dirty
                      }
                    />
                  </WizardPanelWrapper.Actions>
                </WizardPanelWrapper>
              </Wizard.Step>
              <Wizard.Step title="Done">
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
          </Form>
        );
      }}
    </Formik>
  );
};

export default SqsSourceWizard;
