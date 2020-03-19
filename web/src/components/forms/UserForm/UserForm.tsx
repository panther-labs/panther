/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import { Field, Formik } from 'formik';
import { SubmitButton } from 'Components/Buttons';
import { Flex } from 'pouncejs';
import FormikTextInput from 'Components/fields/TextInput';
import * as Yup from 'yup';

interface UserFormValues {
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

const validationSchema = Yup.object().shape({
  email: Yup.string()
    .email('Must be a valid email')
    .required('Email is required'),
  familyName: Yup.string().required('Last name is required'),
  givenName: Yup.string().required('First name is required'),
});

const UserForm: React.FC<UserFormProps> = ({ initialValues, onSubmit }) => {
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

export default UserForm;
