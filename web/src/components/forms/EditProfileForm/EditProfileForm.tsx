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

import * as React from 'react';
import { Alert, Box, SimpleGrid, useSnackbar } from 'pouncejs';
import { Field, Form, Formik } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import SubmitButton from 'Components/buttons/SubmitButton';
import useAuth from 'Hooks/useAuth';
import { useEditUser } from 'Components/sidesheets/EditUserSidesheet/graphql/editUser.generated';
import { extractErrorMessage } from 'Helpers/utils';

interface EditProfileFormProps {
  onSuccess: () => void;
}

interface EditProfileFormValues {
  givenName: string;
  familyName: string;
  email: string;
}

const EditProfileForm: React.FC<EditProfileFormProps> = ({ onSuccess }) => {
  const { userInfo, refetchUserInfo } = useAuth();
  const { pushSnackbar } = useSnackbar();
  const [status, setStatus] = React.useState(null);

  const [editUser] = useEditUser({
    onCompleted: () => {
      onSuccess();
      pushSnackbar({
        variant: 'success',
        title: 'User profile updated successfully',
      });
      return refetchUserInfo();
    },
    onError: updateUserError =>
      setStatus({
        title: 'Unable to update profile',
        message: extractErrorMessage(updateUserError) || 'An unknown error occurred',
      }),
  });

  /* eslint-disable camelcase */
  const initialValues = {
    email: userInfo?.email || '',
    familyName: userInfo?.family_name || '',
    givenName: userInfo?.given_name || '',
  };
  /* eslint-enable camelcase */

  return (
    <Formik<EditProfileFormValues>
      initialValues={initialValues}
      onSubmit={async values =>
        editUser({
          variables: {
            input: {
              id: userInfo.sub,
              familyName: values.familyName,
              givenName: values.givenName,
            },
          },
        })
      }
    >
      <Form>
        {status && (
          <Box mb={4}>
            <Alert variant="error" title={status.title} description={status.message} />
          </Box>
        )}
        <Field
          as={FormikTextInput}
          label="Email address"
          placeholder="john@doe.com"
          disabled
          name="email"
          required
          readonly
        />
        <SimpleGrid my={4} columns={2} gap={4}>
          <Field
            as={FormikTextInput}
            label="First Name"
            placeholder="John"
            name="givenName"
            required
          />
          <Field
            as={FormikTextInput}
            label="Last Name"
            placeholder="Doe"
            name="familyName"
            required
          />
        </SimpleGrid>
        <SubmitButton fullWidth>Update</SubmitButton>
      </Form>
    </Formik>
  );
};

export default EditProfileForm;
