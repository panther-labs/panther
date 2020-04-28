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

import * as Yup from 'yup';
import { Field, Formik } from 'formik';
import React from 'react';
import { Box } from 'pouncejs';
import FormikTextInput from 'Components/fields/TextInput';
import SubmitButton from 'Components/buttons/SubmitButton';
import useAuth from 'Hooks/useAuth';

interface SignInFormValues {
  username: string;
  password: string;
}

const initialValues = {
  username: '',
  password: '',
};

const validationSchema = Yup.object().shape({
  username: Yup.string()
    .email('Needs to be a valid email')
    .required(),
  password: Yup.string().required(),
});

const SignInForm: React.FC = () => {
  const { signIn } = useAuth();

  return (
    <Formik<SignInFormValues>
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={async ({ username, password }, { setErrors }) =>
        signIn({
          email: username,
          password,
          onError: ({ message }) =>
            setErrors({
              password: message,
            }),
        })
      }
    >
      {({ handleSubmit, isSubmitting, isValid, dirty }) => (
        <Box width={1} as="form" onSubmit={handleSubmit}>
          <Field
            as={FormikTextInput}
            label="Email"
            placeholder="Enter your company email..."
            type="email"
            name="username"
            aria-required
            mb={6}
          />
          <Field
            as={FormikTextInput}
            label="Password"
            placeholder="The name of your cat"
            name="password"
            type="password"
            aria-required
            mb={6}
          />
          <SubmitButton
            width={1}
            submitting={isSubmitting}
            disabled={isSubmitting || !isValid || !dirty}
          >
            Sign in
          </SubmitButton>
        </Box>
      )}
    </Formik>
  );
};

export default SignInForm;
