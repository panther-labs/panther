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

import { Alert, Flex } from 'pouncejs';
import { Field, Form, Formik } from 'formik';
import React from 'react';
import * as Yup from 'yup';
import { createYupPasswordValidationSchema } from 'Helpers/utils';
import SubmitButton from 'Components/buttons/SubmitButton';
import FormikTextInput from 'Components/fields/TextInput';
import useAuth from 'Hooks/useAuth';

interface ChangePasswordFormProps {
  onSuccess: () => void;
}

interface ChangePasswordFormValues {
  oldPassword: string;
  confirmNewPassword: string;
  newPassword: string;
}

const initialValues = {
  oldPassword: '',
  newPassword: '',
  confirmNewPassword: '',
};

const validationSchema = Yup.object().shape({
  oldPassword: createYupPasswordValidationSchema(),
  newPassword: createYupPasswordValidationSchema(),
  confirmNewPassword: createYupPasswordValidationSchema().oneOf(
    [Yup.ref('newPassword')],
    "Passwords don't match"
  ),
});

const ChangePasswordForm: React.FC<ChangePasswordFormProps> = ({ onSuccess }) => {
  const { changePassword, signOut } = useAuth();

  return (
    <Formik<ChangePasswordFormValues>
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={async ({ oldPassword, newPassword }, { setStatus }) =>
        changePassword({
          oldPassword,
          newPassword,
          onSuccess: () => {
            signOut({ global: true });
            onSuccess();
          },
          onError: ({ message }) =>
            setStatus({
              title: 'Update password failed.',
              message,
            }),
        })
      }
    >
      {({ status }) => (
        <Form>
          <Flex direction="column" spacing={4}>
            <Alert
              variant="default"
              title="Updating your password will log you out of all devices!"
            />
            {status && <Alert variant="error" title={status.title} description={status.message} />}
            <Field
              as={FormikTextInput}
              label="Current Password"
              placeholder="Enter your current password..."
              type="password"
              name="oldPassword"
              required
            />
            <Field
              as={FormikTextInput}
              label="New Password"
              placeholder="Type your new password..."
              type="password"
              name="newPassword"
              required
            />
            <Field
              as={FormikTextInput}
              label="Confirm New Password"
              placeholder="Type your new password again..."
              type="password"
              name="confirmNewPassword"
              required
            />
            <SubmitButton fullWidth>Change password</SubmitButton>
          </Flex>
        </Form>
      )}
    </Formik>
  );
};

export default ChangePasswordForm;
