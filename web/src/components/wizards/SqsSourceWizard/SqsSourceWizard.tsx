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
import { Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FetchResult } from '@apollo/client';
import { Wizard } from 'Components/Wizard';
import { yupIntegrationLabelValidation } from 'Helpers/utils';
import SqsSourceConfigurationPanel from './SqsSourceConfigurationPanel';
import ValidationPanel from './ValidationPanel';

interface SqsLogSourceWizardProps {
  initialValues: SqsLogSourceWizardValues;
  onSubmit: (values: SqsLogSourceWizardValues) => Promise<FetchResult<any>>;
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
  logTypes: Yup.array().of(Yup.string()).required(),
  allowedPrincipalArns: Yup.array().of(Yup.string()),
  allowedSourceArns: Yup.array().of(Yup.string()),
});

const SqsSourceWizard: React.FC<SqsLogSourceWizardProps> = ({ initialValues, onSubmit }) => {
  return (
    <Formik<SqsLogSourceWizardValues>
      enableReinitialize
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={onSubmit}
    >
      <Form>
        <Wizard>
          <Wizard.Step title="Configure">
            <SqsSourceConfigurationPanel />
          </Wizard.Step>
          <Wizard.Step title="Done">
            <ValidationPanel />
          </Wizard.Step>
        </Wizard>
      </Form>
    </Formik>
  );
};

export default SqsSourceWizard;
