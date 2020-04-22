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
import SubmitButton from 'Components/buttons/SubmitButton';
import { Flex } from 'pouncejs';
import FormikTextInput from 'Components/fields/TextInput';
import * as Yup from 'yup';
import { useListUsers } from 'Pages/Users';

export interface UserFormValues {
  id?: string; // optional value
  email: string;
  familyName: string;
  givenName;
}
export interface UserFormProps {
  /** The initial values of the form */
  initialValues: UserFormValues;

  /** callback for the submission of the form */
  onSubmit: (values: UserFormValues) => void;
}

const UserForm: React.FC<UserFormProps> = ({ initialValues, onSubmit }) => {
  /*
   This is temporal fix for inviting OR editing users that already exist
   when this is fixed we should revert it: https://github.com/apollographql/apollo-client/issues/5790
   */
  const { data } = useListUsers();
  const userEmails = data.users.map(u => u.email);

  const validationSchema = Yup.object().shape({
    email: Yup.string()
      .email('Must be a valid email')
      .required('Email is required')
      .notOneOf(userEmails, 'Email already in use'),
    familyName: Yup.string().required('Last name is required'),
    givenName: Yup.string().required('First name is required'),
  });

  return (
    <Formik<UserFormValues>
      initialValues={initialValues}
      onSubmit={onSubmit}
      enableReinitialize
      validationSchema={validationSchema}
    >
      {({ handleSubmit, isSubmitting, isValid, dirty }) => {
        return (
          <form onSubmit={handleSubmit}>
            <Field
              as={FormikTextInput}
              label="Email address"
              placeholder="john@doe.com"
              name="email"
              aria-required
              mb={3}
            />
            <Flex mb={6} justify="space-between">
              <Field
                as={FormikTextInput}
                label="First Name"
                placeholder="John"
                name="givenName"
                aria-required
              />
              <Field
                as={FormikTextInput}
                label="Last Name"
                placeholder="Doe"
                name="familyName"
                aria-required
              />
            </Flex>
            <Flex borderTop="1px solid" borderColor="grey100" pt={6} mt={10} justify="flex-end">
              <SubmitButton
                submitting={isSubmitting}
                disabled={!dirty || !isValid || isSubmitting}
                width={1}
              >
                {initialValues.id ? 'Update' : 'Invite'}
              </SubmitButton>
            </Flex>
          </form>
        );
      }}
    </Formik>
  );
};

export default UserForm;
