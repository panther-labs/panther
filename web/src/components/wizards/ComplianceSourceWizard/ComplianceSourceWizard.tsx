/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
import { Form, Formik } from 'formik';
import * as Yup from 'yup';
import { Wizard } from 'Components/Wizard';
import { FetchResult } from '@apollo/client';
import { yupIntegrationLabelValidation } from 'Helpers/utils';
import StackDeploymentPanel from './StackDeploymentPanel';
import ValidationPanel from './ValidationPanel';
import SourceConfigurationPanel from './SourceConfigurationPanel';

interface ComplianceSourceWizardProps {
  initialValues: ComplianceSourceWizardValues;
  onSubmit: (values: ComplianceSourceWizardValues) => Promise<FetchResult<any>>;
}

export interface ComplianceSourceWizardValues {
  integrationId?: string;
  awsAccountId: string;
  integrationLabel: string;
  cweEnabled: boolean;
  remediationEnabled: boolean;
}

const validationSchema = Yup.object().shape<ComplianceSourceWizardValues>({
  integrationLabel: yupIntegrationLabelValidation,
  awsAccountId: Yup.string()
    .matches(AWS_ACCOUNT_ID_REGEX, 'Must be a valid AWS Account ID')
    .required(),
  cweEnabled: Yup.boolean().required(),
  remediationEnabled: Yup.boolean().required(),
});

const ComplianceSourceWizard: React.FC<ComplianceSourceWizardProps> = ({
  initialValues,
  onSubmit,
}) => {
  return (
    <Formik<ComplianceSourceWizardValues>
      enableReinitialize
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={onSubmit}
    >
      <Form>
        <Wizard>
          <Wizard.Step title="Configure Source">
            <SourceConfigurationPanel />
          </Wizard.Step>
          <Wizard.Step title="Setup IAM Roles">
            <StackDeploymentPanel />
          </Wizard.Step>
          <Wizard.Step title="Verify Setup">
            <ValidationPanel />
          </Wizard.Step>
        </Wizard>
      </Form>
    </Formik>
  );
};

export default ComplianceSourceWizard;
