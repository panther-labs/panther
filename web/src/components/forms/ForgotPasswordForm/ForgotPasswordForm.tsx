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
import SubmitButton from 'Components/buttons/SubmitButton';
import FormikTextInput from 'Components/fields/TextInput';
import useAuth from 'Hooks/useAuth';
import { Card, Flex, FormHelperText } from 'pouncejs';

interface ForgotPasswordFormValues {
  email: string;
}

const initialValues = {
  email: '',
};

const validationSchema = Yup.object().shape({
  email: Yup.string().email('Needs to be a valid email').required(),
});

const ForgotPasswordForm: React.FC = () => {
  const { forgotPassword } = useAuth();

  return (
    <Formik<ForgotPasswordFormValues>
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={async ({ email }, { setErrors, setStatus }) =>
        forgotPassword({
          email,
          onSuccess: () => setStatus('SENT'),
          onError: ({ message }) => setErrors({ email: message }),
        })
      }
    >
      {({ status, values }) => {
        if (status === 'SENT') {
          return (
            <Card bg="teal-500" p={5} mb={8} boxShadow="none" fontSize="medium">
              We have successfully sent you an email with reset instructions at{' '}
              <b>{values.email}</b>
            </Card>
          );
        }

        return (
          <Form>
            <Flex direction="column" spacing={4}>
              <Field
                as={FormikTextInput}
                label="Email"
                placeholder="Enter your company email..."
                type="email"
                name="email"
                required
              />
              <SubmitButton fullWidth aria-describedby="forgot-password-description">
                Reset Password
              </SubmitButton>
              <FormHelperText id="forgot-password-description" textAlign="center">
                By submitting a request, you will receive an email with instructions on how to reset
                your password
              </FormHelperText>
            </Flex>
          </Form>
        );
      }}
    </Formik>
  );
};

export default ForgotPasswordForm;
