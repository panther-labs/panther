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
import * as Yup from 'yup';
import { useMutation, gql } from '@apollo/client';
import { Field, Formik } from 'formik';
import { Alert, Box, Flex, useSnackbar } from 'pouncejs';
import { RoleNameEnum, InviteUserInput } from 'Generated/schema';
import { LIST_USERS } from 'Pages/users/subcomponents/list-users-table';
import SubmitButton from 'Components/submit-button';
import { getOperationName } from '@apollo/client/utilities/graphql/getFromAST';
import FormikTextInput from 'Components/fields/text-input';
import FormikCombobox from 'Components/fields/combobox';
import { extractErrorMessage } from 'Helpers/utils';

const INVITE_USER = gql`
  mutation InviteUser($input: InviteUserInput!) {
    inviteUser(input: $input) {
      id
    }
  }
`;

interface ApolloMutationInput {
  input: InviteUserInput;
}

interface UserInvitationFormValues {
  email?: string;
  familyName?: string;
  givenName?: string;
  role?: RoleNameEnum;
}

interface UserInvitationFormProps {
  onSuccess: () => void;
}

const initialValues = {
  email: '',
  familyName: '',
  givenName: '',
  role: RoleNameEnum.Admin,
};

const validationSchema = Yup.object().shape({
  email: Yup.string().required('Email is required'),
  familyName: Yup.string().required('Last name is required'),
  givenName: Yup.string().required('First name is required'),
  role: Yup.string().required('Role is required'),
});

export const UserInvitationForm: React.FC<UserInvitationFormProps> = ({ onSuccess }) => {
  const [inviteUser, { error: inviteUserError, data }] = useMutation<boolean, ApolloMutationInput>(
    INVITE_USER
  );
  const { pushSnackbar } = useSnackbar();

  React.useEffect(() => {
    if (data) {
      pushSnackbar({ variant: 'success', title: `Successfully invited user` });
      onSuccess();
    }
  }, [data]);

  return (
    <Formik<UserInvitationFormValues>
      validationSchema={validationSchema}
      initialValues={initialValues}
      onSubmit={async values => {
        await inviteUser({
          variables: {
            input: {
              email: values.email,
              familyName: values.familyName,
              givenName: values.givenName,
              role: values.role,
            },
          },
          refetchQueries: [getOperationName(LIST_USERS)],
        });
      }}
    >
      {({ handleSubmit, isSubmitting, dirty, isValid }) => (
        <form onSubmit={handleSubmit}>
          {inviteUserError && (
            <Alert
              variant="error"
              title="Failed to invite user"
              description={
                extractErrorMessage(inviteUserError) ||
                'Failed to invite user due to an unforeseen error'
              }
              mb={6}
            />
          )}
          <Box mb={8}>
            <Flex justifyContent="space-between">
              <Field name="givenName" as={FormikTextInput} label="First Name" />
              <Field name="familyName" as={FormikTextInput} label="Family Name" />
            </Flex>
            <Field name="email" as={FormikTextInput} type="email" label="Email" />
            <Field name="role" as={FormikCombobox} label="Role" items={[[RoleNameEnum.Admin]]} />
          </Box>
          <SubmitButton
            width={1}
            disabled={isSubmitting || !isValid || !dirty}
            submitting={isSubmitting}
          >
            Invite User
          </SubmitButton>
        </form>
      )}
    </Formik>
  );
};

export default UserInvitationForm;
