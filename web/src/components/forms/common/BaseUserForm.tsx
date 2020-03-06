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
import SubmitButton from 'Components/SubmitButton';
import { Flex } from 'pouncejs';
import FormikTextInput from 'Components/fields/TextInput';
import * as Yup from 'yup';

interface BaseUserFormValues {
  id?: string; // optional value
  email: string;
  familyName: string;
  givenName;
}
export interface BaseUserFormProps {
  /** The initial values of the form */
  initialValues: BaseUserFormValues;

  /** callback for the submission of the form */
  onSubmit: (values: BaseUserFormValues) => void;
}

const validationSchema = Yup.object().shape({
  email: Yup.string()
    .email('Must be a valid email')
    .required('Email is required'),
  familyName: Yup.string().required('Last name is required'),
  givenName: Yup.string().required('First name is required'),
});

const BaseUserForm: React.FC<BaseUserFormProps> = ({ initialValues, onSubmit }) => {
  return (
    <Formik<BaseUserFormValues>
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
            <Flex mb={6} justifyContent="space-between">
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
            <Flex
              borderTop="1px solid"
              borderColor="grey100"
              pt={6}
              mt={10}
              justifyContent="flex-end"
            >
              <Flex>
                <SubmitButton
                  submitting={isSubmitting}
                  disabled={!dirty || !isValid || isSubmitting}
                >
                  {initialValues.id ? 'Update' : 'Invite'}
                </SubmitButton>
              </Flex>
            </Flex>
          </form>
        );
      }}
    </Formik>
  );
};

export default BaseUserForm;
