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
import { Field, Form, Formik } from 'formik';
import { Link as RRLink } from 'react-router-dom';
import React from 'react';
import FormikTextInput from 'Components/fields/TextInput';
import SubmitButton from 'Components/buttons/SubmitButton';
import useAuth from 'Hooks/useAuth';
import { Link, Flex, Box } from 'pouncejs';
import urls from 'Source/urls';

interface SignInFormValues {
  username: string;
  password: string;
}

const initialValues = {
  username: '',
  password: '',
};

const validationSchema = Yup.object().shape({
  username: Yup.string().email('Needs to be a valid email').required(),
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
          onError: ({ message }) => {
            // FIXME: There is weird issue returning wrong error message on submit
            // correlated heavily on this https://github.com/aws-amplify/amplify-js/pull/4427
            return setErrors({
              password:
                message === 'Only radix 2, 4, 8, 16, 32 are supported'
                  ? 'Incorrect username or password.'
                  : message,
            });
          },
        })
      }
    >
      <Form>
        <Flex direction="column" spacing={4}>
          <Field
            as={FormikTextInput}
            label="Email"
            placeholder="Enter your company email..."
            type="email"
            name="username"
            required
          />
          <Field
            as={FormikTextInput}
            label="Password"
            placeholder="The name of your cat"
            name="password"
            type="password"
            required
          />
          <Flex ml="auto">
            <Link as={RRLink} to={urls.account.auth.forgotPassword()} fontSize="medium">
              Forgot your password?
            </Link>
          </Flex>
          <Box mt={4}>
            <SubmitButton fullWidth>Sign in</SubmitButton>
          </Box>
        </Flex>
      </Form>
    </Formik>
  );
};

export default SignInForm;
