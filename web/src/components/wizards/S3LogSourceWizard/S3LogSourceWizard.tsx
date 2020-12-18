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
import { AWS_ACCOUNT_ID_REGEX, S3_BUCKET_NAME_REGEX } from 'Source/constants';
import { Form, Formik } from 'formik';
import * as Yup from 'yup';
import { Wizard } from 'Components/Wizard';
import { FetchResult } from '@apollo/client';
import { getArnRegexForService, yupIntegrationLabelValidation } from 'Helpers/utils';
import { S3PrefixLogTypes } from 'Generated/schema';
import StackDeploymentPanel from './StackDeploymentPanel';
import S3SourceConfigurationPanel from './S3SourceConfigurationPanel';
import ValidationPanel from './ValidationPanel';

interface S3LogSourceWizardProps {
  initialValues: S3LogSourceWizardValues;
  onSubmit: (values: S3LogSourceWizardValues) => Promise<FetchResult<any>>;
}

export interface S3LogSourceWizardValues {
  // for updates
  integrationId?: string;
  initialStackName?: string;
  // common for creation + updates
  awsAccountId: string;
  integrationLabel: string;
  s3Bucket: string;
  kmsKey: string;
  s3PrefixLogTypes: S3PrefixLogTypes[];
}

const validationSchema = Yup.object().shape<S3LogSourceWizardValues>({
  integrationLabel: yupIntegrationLabelValidation,
  awsAccountId: Yup.string()
    .matches(AWS_ACCOUNT_ID_REGEX, 'Must be a valid AWS Account ID')
    .required(),
  s3Bucket: Yup.string().matches(S3_BUCKET_NAME_REGEX, 'Must be valid S3 Bucket name').required(),
  s3PrefixLogTypes: Yup.array()
    .of(
      Yup.object().shape({
        prefix: Yup.string(),
        logTypes: Yup.array().of(Yup.string()).required(),
      })
    )
    .required(),
  kmsKey: Yup.string().matches(getArnRegexForService('KMS'), 'Must be a valid KMS ARN'),
});

const S3LogSourceWizard: React.FC<S3LogSourceWizardProps> = ({ initialValues, onSubmit }) => {
  return (
    <Formik<S3LogSourceWizardValues>
      enableReinitialize
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={onSubmit}
    >
      <Form>
        <Wizard>
          <Wizard.Step title="Configure Source">
            <S3SourceConfigurationPanel />
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

export default S3LogSourceWizard;
