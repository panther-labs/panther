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
import { Field, Formik } from 'formik';
import * as Yup from 'yup';
import SubmitButton from 'Components/buttons/SubmitButton';
import FormikTextInput from 'Components/fields/TextInput';
import useAuth from 'Hooks/useAuth';
import { Card, Text } from 'pouncejs';

interface ForgotPasswordFormValues {
  email: string;
}

const initialValues = {
  email: '',
};

const validationSchema = Yup.object().shape({
  email: Yup.string()
    .email('Needs to be a valid email')
    .required(),
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
          onError: ({ code, message }) => {
            setErrors({
              email:
                code === 'UserNotFoundException'
                  ? "We couldn't find this Panther account"
                  : message,
            });
          },
        })
      }
    >
      {({ handleSubmit, isSubmitting, isValid, dirty, status, values }) => {
        if (status === 'SENT') {
          return (
            <Card bg="green100" p={5} mb={8} boxShadow="none">
              <Text color="green300" size="large">
                We have successfully sent you an email with reset instructions at{' '}
                <b>{values.email}</b>
              </Text>
            </Card>
          );
        }

        return (
          <form onSubmit={handleSubmit}>
            <Field
              as={FormikTextInput}
              label="Email"
              placeholder="Enter your company email..."
              type="email"
              name="email"
              aria-required
              mb={6}
            />
            <SubmitButton
              width={1}
              submitting={isSubmitting}
              disabled={isSubmitting || !isValid || !dirty}
            >
              Reset Password
            </SubmitButton>
          </form>
        );
      }}
    </Formik>
  );
};

export default ForgotPasswordForm;
