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
import { Field, Formik } from 'formik';
import * as Yup from 'yup';
import { Alert, Box, useSnackbar } from 'pouncejs';
import SubmitButton from 'Components/buttons/SubmitButton';
import FormikTextInput from 'Components/fields/TextInput';
import useRouter from 'Hooks/useRouter';
import useAuth from 'Hooks/useAuth';
import urls from 'Source/urls';

interface ForgotPasswordConfirmFormProps {
  email: string;
  token: string;
}

interface ForgotPasswordConfirmFormValues {
  newPassword: string;
  confirmNewPassword: string;
}

const validationSchema = Yup.object().shape({
  newPassword: Yup.string().required(),
  confirmNewPassword: Yup.string()
    .oneOf([Yup.ref('newPassword')], 'Passwords must match')
    .required(),
});

const ForgotPasswordConfirmForm: React.FC<ForgotPasswordConfirmFormProps> = ({ email, token }) => {
  const { history } = useRouter();
  const { resetPassword } = useAuth();
  const { pushSnackbar } = useSnackbar();

  const initialValues = {
    newPassword: '',
    confirmNewPassword: '',
  };

  return (
    <Formik<ForgotPasswordConfirmFormValues>
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={({ newPassword }, { setStatus }) =>
        resetPassword({
          email,
          token,
          newPassword,
          onSuccess: () => {
            pushSnackbar({ variant: 'info', title: 'Password changed successfully!' });
            history.replace(urls.account.auth.signIn());
          },
          onError: ({ message }) =>
            setStatus({
              title: 'Houston, we have a problem',
              message,
            }),
        })
      }
    >
      {({ isValid, handleSubmit, isSubmitting, status, dirty }) => (
        <Box as="form" width={1} onSubmit={handleSubmit}>
          {status && (
            <Alert variant="error" title={status.title} description={status.message} mb={6} />
          )}
          <Field
            as={FormikTextInput}
            label="New Password"
            placeholder="Type your new password..."
            type="password"
            name="newPassword"
            autoco
            aria-required
            autoComplete="new-password"
            mb={6}
          />
          <Field
            as={FormikTextInput}
            label="Confirm New Password"
            placeholder="Type your new password again..."
            type="password"
            name="confirmNewPassword"
            aria-required
            autoComplete="new-password"
            mb={6}
          />
          <SubmitButton
            width={1}
            submitting={isSubmitting}
            disabled={isSubmitting || !isValid || !dirty}
          >
            Update password
          </SubmitButton>
        </Box>
      )}
    </Formik>
  );
};

export default ForgotPasswordConfirmForm;
