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
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { Alert, Box, Flex, TextInput, useSnackbar } from 'pouncejs';
import SubmitButton from 'Components/buttons/SubmitButton';
import FormikTextInput from 'Components/fields/TextInput';
import useRouter from 'Hooks/useRouter';
import useAuth from 'Hooks/useAuth';
import urls from 'Source/urls';
import { yupPasswordValidationSchema } from 'Helpers/utils';
import FieldPolicyChecker from 'Components/FieldPolicyChecker/FieldPolicyChecker';

interface ForgotPasswordConfirmFormProps {
  email: string;
  token: string;
}

interface ForgotPasswordConfirmFormValues {
  newPassword: string;
  confirmNewPassword: string;
}

const validationSchema = Yup.object().shape({
  newPassword: yupPasswordValidationSchema,
  confirmNewPassword: yupPasswordValidationSchema.oneOf(
    [Yup.ref('newPassword')],
    'Passwords must match'
  ),
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
      {({ status, values }) => (
        <Form>
          <Flex direction="column" spacing={4}>
            {status && <Alert variant="error" title={status.title} description={status.message} />}
            <Field
              as={TextInput}
              label="New Password"
              placeholder="Type your new password..."
              type="password"
              name="newPassword"
              required
              autoComplete="new-password"
            />
            <Field
              as={FormikTextInput}
              label="Confirm New Password"
              placeholder="Type your new password again..."
              type="password"
              name="confirmNewPassword"
              required
              autoComplete="new-password"
            />
            <Box py={3}>
              <FieldPolicyChecker schema={yupPasswordValidationSchema} value={values.newPassword} />
            </Box>
            <SubmitButton fullWidth>Update password</SubmitButton>
          </Flex>
        </Form>
      )}
    </Formik>
  );
};

export default ForgotPasswordConfirmForm;
