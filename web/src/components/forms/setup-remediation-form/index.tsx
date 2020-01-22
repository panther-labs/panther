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
import * as Yup from 'yup';
import { FastField as Field, Formik } from 'formik';
import { Box, Button } from 'pouncejs';
import { AWS_ACCOUNT_ID_REGEX, PANTHER_REMEDIATION_SATELLITE_ACCOUNT } from 'Source/constants';
import FormikTextInput from 'Components/fields/text-input';

interface SetupRemediationFormValues {
  awsAccountId: string;
}

interface SetupRemediationFormProps {
  onStackLaunch: () => void;
}

const initialValues = {
  awsAccountId: '',
};

const validationSchema = Yup.object().shape({
  awsAccountId: Yup.string()
    .matches(AWS_ACCOUNT_ID_REGEX, 'Must be a valid AWS Account ID')
    .required(),
});

const SetupRemediationForm: React.FC<SetupRemediationFormProps> = ({ onStackLaunch }) => {
  return (
    <Formik<SetupRemediationFormValues>
      initialValues={initialValues}
      onSubmit={() => {}}
      validationSchema={validationSchema}
    >
      {({ handleSubmit, values: { awsAccountId } }) => {
        const cfnLink =
          `https://us-west-2.console.aws.amazon.com/cloudformation/home?region=us-west-2#/stacks/create/review` +
          `?templateURL=https://s3-us-west-2.amazonaws.com/panther-public-cloudformation-templates/${PANTHER_REMEDIATION_SATELLITE_ACCOUNT}/latest/template.yml` +
          `&stackName=${PANTHER_REMEDIATION_SATELLITE_ACCOUNT}` +
          `&param_MasterAccountId=${awsAccountId}`;

        return (
          <form onSubmit={handleSubmit}>
            <Box mb={8} width={0.6}>
              <Field
                as={FormikTextInput}
                label="Your Auto-Remediation Master AWS Account ID"
                name="awsAccountId"
                placeholder="i.e. 548784460855"
                aria-required
              />
            </Box>
            <Button
              size="large"
              variant="default"
              target="_blank"
              is="a"
              rel="noopener noreferrer"
              href={cfnLink}
              onClick={onStackLaunch}
            >
              Launch Stack
            </Button>
          </form>
        );
      }}
    </Formik>
  );
};

export default React.memo(SetupRemediationForm);
