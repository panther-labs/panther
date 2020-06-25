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

import { Field, Form, Formik } from 'formik';
import React from 'react';
import * as Yup from 'yup';
import { createYupPasswordValidationSchema } from 'Helpers/utils';
import { Alert, Box, Link, Text } from 'pouncejs';
import SubmitButton from 'Components/buttons/SubmitButton';
import FormikTextInput from 'Components/fields/TextInput';
import useAuth from 'Hooks/useAuth';

interface SetPasswordFormValues {
  confirmNewPassword: string;
  newPassword: string;
  formErrors?: string[];
}

const initialValues = {
  confirmNewPassword: '',
  newPassword: '',
};

const validationSchema = Yup.object().shape({
  confirmNewPassword: createYupPasswordValidationSchema().oneOf(
    [Yup.ref('newPassword')],
    'Passwords must match'
  ),
  newPassword: createYupPasswordValidationSchema(),
});

const SetPasswordForm: React.FC = () => {
  const { setNewPassword } = useAuth();

  return (
    <Formik<SetPasswordFormValues>
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={async ({ newPassword }, { setStatus }) =>
        setNewPassword({
          newPassword,
          onError: ({ message }) =>
            setStatus({
              title: 'Update password failed',
              message,
            }),
        })
      }
    >
      {({ status }) => (
        <Form>
          {status && (
            <Box mb={4}>
              <Alert variant="error" title={status.title} description={status.message} />
            </Box>
          )}
          <Box mb={4}>
            <Field
              as={FormikTextInput}
              label="New Password"
              placeholder="Type your new password..."
              type="password"
              name="newPassword"
              required
            />
          </Box>
          <Box mb={4}>
            <Field
              as={FormikTextInput}
              label="Confirm New Password"
              placeholder="Your new password again..."
              type="password"
              name="confirmNewPassword"
              required
            />
          </Box>
          <SubmitButton fullWidth>Set password</SubmitButton>
          <Text size="small" mt={4} color="gray-200">
            By continuing, you agree to Panther&apos;s&nbsp;
            <Link
              external
              href="https://panther-public-shared-assets.s3-us-west-2.amazonaws.com/EULA.pdf"
            >
              End User License Agreement
            </Link>{' '}
            and acknowledge you have read the&nbsp;
            <Link
              external
              href="https://panther-public-shared-assets.s3-us-west-2.amazonaws.com/PrivacyPolicy.pdf"
            >
              Privacy Policy
            </Link>
          </Text>
        </Form>
      )}
    </Formik>
  );
};

export default SetPasswordForm;
