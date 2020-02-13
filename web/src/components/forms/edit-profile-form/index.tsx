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

import * as React from 'react';
import { Alert, Box, Flex, useSnackbar } from 'pouncejs';
import { Field, Formik } from 'formik';
import FormikTextInput from 'Components/fields/text-input';
import SubmitButton from 'Components/submit-button';
import useAuth from 'Hooks/useAuth';

interface EditProfileFormProps {
  onSuccess: () => void;
}

interface EditProfileFormValues {
  givenName: string;
  familyName: string;
  email: string;
}

const EditProfileForm: React.FC<EditProfileFormProps> = ({ onSuccess }) => {
  const { userInfo, updateUserInfo } = useAuth();
  const { pushSnackbar } = useSnackbar();

  const initialValues = {
    email: userInfo.email || '',
    familyName: userInfo.family_name || '',
    givenName: userInfo.given_name || '',
  };

  return (
    <Formik<EditProfileFormValues>
      initialValues={initialValues}
      onSubmit={async ({ givenName, familyName }, { setStatus }) =>
        updateUserInfo({
          newAttributes: {
            given_name: givenName,
            family_name: familyName,
          },
          onSuccess: () => {
            onSuccess();
            pushSnackbar({ title: 'Successfully updated profile!', variant: 'success' });
          },
          onError: ({ message }) =>
            setStatus({
              title: 'Unable to update profile',
              message,
            }),
        })
      }
    >
      {({ handleSubmit, status, isSubmitting, isValid, dirty }) => (
        <Box is="form" onSubmit={handleSubmit}>
          {status && (
            <Alert variant="error" title={status.title} description={status.message} mb={6} />
          )}
          <Field
            as={FormikTextInput}
            label="Email address"
            placeholder="john@doe.com"
            disabled
            name="email"
            aria-required
            readonly
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
          <SubmitButton
            width={1}
            submitting={isSubmitting}
            disabled={isSubmitting || !isValid || !dirty}
          >
            Update
          </SubmitButton>
        </Box>
      )}
    </Formik>
  );
};

export default EditProfileForm;
