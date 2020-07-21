/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import { LOG_TYPES } from 'Source/constants';
import { Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FetchResult } from '@apollo/client';
import { Wizard, WizardPanelWrapper } from 'Components/Wizard';
import { integrationLabelValidation } from 'Helpers/utils';
import SuccessPanel from './SuccessPanel';
import SqsSourceConfigurationPanel from './SqsSourceConfigurationPanel';

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
  allowedPrincipals: string[];
  allowedSourceArns: string[];
  queueUrl?: string;
}

const validationSchema = Yup.object().shape<SqsLogSourceWizardValues>({
  integrationLabel: integrationLabelValidation(),
  logTypes: Yup.array()
    .of(Yup.string().oneOf((LOG_TYPES as unknown) as string[]))
    .required(),
  allowedPrincipals: Yup.array().of(Yup.string()).required(),
  allowedSourceArns: Yup.array().of(Yup.string()).required(),
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
      {({ isValid, dirty, status, setStatus }) => {
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
              <Wizard.Step title="Configure" icon="settings">
                <WizardPanelWrapper>
                  <WizardPanelWrapper.Content>
                    <SqsSourceConfigurationPanel />
                  </WizardPanelWrapper.Content>
                  <WizardPanelWrapper.Actions>
                    <WizardPanelWrapper.ActionNext disabled={!dirty || !isValid} />
                  </WizardPanelWrapper.Actions>
                </WizardPanelWrapper>
              </Wizard.Step>
              <Wizard.Step title="Done" icon="check">
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
