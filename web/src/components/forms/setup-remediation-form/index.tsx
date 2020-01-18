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
import { Box, Button, Flex, InputElementLabel } from 'pouncejs';
import { AWS_ACCOUNT_ID_REGEX } from 'Source/constants';
import FormikCheckbox from 'Components/fields/checkbox';
import FormikTextInput from 'Components/fields/text-input';

interface SetupRemediationFormValues {
  isSatellite: boolean;
  adminAWSAccountId: string;
}

interface SetupRemediationFormProps {
  getStackUrl: (values: SetupRemediationFormValues) => string;
  onStackLaunch?: () => void;
}

const initialValues = {
  isSatellite: false,
  adminAWSAccountId: '',
};

const validationSchema = Yup.object().shape({
  isSatellite: Yup.boolean(),
  username: Yup.string()
    .matches(AWS_ACCOUNT_ID_REGEX)
    .required(),
});

const SetupRemediationForm: React.FC<SetupRemediationFormProps> = ({
  getStackUrl,
  onStackLaunch,
}) => {
  return (
    <Formik<SetupRemediationFormValues>
      initialValues={initialValues}
      onSubmit={() => {}}
      validationSchema={validationSchema}
    >
      {({ handleSubmit, values }) => (
        <Box is="form" onSubmit={handleSubmit}>
          <Flex mb={6} alignItems="center">
            <InputElementLabel htmlFor="isSatellite" mr={3}>
              I want to setup automatic remediation in a satellite account
            </InputElementLabel>
            <Field as={FormikCheckbox} id="isSatellite" name="isSatellite" />
          </Flex>
          <Box hidden={!values.isSatellite} mb={10} width={0.3}>
            <Field
              as={FormikTextInput}
              label="Your Auto-Remediation Master AWS Account ID"
              name="adminAWSAccountId"
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
            href={getStackUrl(values)}
            onClick={onStackLaunch}
          >
            Launch Stack
          </Button>
        </Box>
      )}
    </Formik>
  );
};

export default React.memo(SetupRemediationForm);
