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
import { UpdateUserInput, User } from 'Generated/schema';
import { Field, Formik } from 'formik';
import FormikTextInput from 'Components/fields/text-input';
import SubmitButton from 'Components/submit-button';
import { gql, useMutation } from '@apollo/client';
import { getOperationName } from '@apollo/client/utilities/graphql/getFromAST';
import { LIST_USERS } from 'Pages/users/subcomponents/list-users-table';
import { extractErrorMessage } from 'Helpers/utils';

const EDIT_USER = gql`
  mutation EditUser($input: UpdateUserInput!) {
    updateUser(input: $input)
  }
`;

interface ApolloMutationInput {
  input: UpdateUserInput;
}

interface EditProfileFormProps {
  onSuccess: () => void;
  user: User;
}

interface EditProfileFormValues {
  id: string;
  givenName: string;
  familyName: string;
  email: string;
}

const EditProfileForm: React.FC<EditProfileFormProps> = ({ onSuccess, user }) => {
  const [editUser, { error: editUserError, data }] = useMutation<boolean, ApolloMutationInput>(
    EDIT_USER
  );
  const { pushSnackbar } = useSnackbar();

  React.useEffect(() => {
    if (data) {
      pushSnackbar({ variant: 'success', title: `Successfully edited user` });
      // TODO: Refetch user if updating self
      onSuccess();
    }
  }, [data]);

  const initialValues = {
    id: user.id,
    email: user.email || '',
    familyName: user.familyName || '',
    givenName: user.givenName || '',
  };

  return (
    <Formik<EditProfileFormValues>
      initialValues={initialValues}
      onSubmit={async values => {
        await editUser({
          variables: {
            input: {
              id: values.id,
              email: values.email,
              familyName: values.familyName,
              givenName: values.givenName,
            },
          },
          refetchQueries: [getOperationName(LIST_USERS)],
        });
      }}
    >
      {({ handleSubmit, isSubmitting, isValid, dirty }) => (
        <Box is="form" onSubmit={handleSubmit}>
          {editUserError && (
            <Alert
              variant="error"
              title="Failed to invite user"
              description={
                extractErrorMessage(editUserError) ||
                'Failed to edit user due to an unforeseen error'
              }
              mb={6}
            />
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
