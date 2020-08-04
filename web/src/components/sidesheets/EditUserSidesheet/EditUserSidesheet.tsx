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
import { Box, Heading, SideSheet, SideSheetProps, useSnackbar } from 'pouncejs';
import { extractErrorMessage } from 'Helpers/utils';
import UserForm, { UserFormValues } from 'Components/forms/UserForm';
import useAuth from 'Hooks/useAuth';
import { UserDetails } from 'Source/graphql/fragments/UserDetails.generated';
import { useEditUser } from './graphql/editUser.generated';

export interface EditUserSidesheetProps extends SideSheetProps {
  user: UserDetails;
}

const EditUserSidesheet: React.FC<EditUserSidesheetProps> = ({ user, onClose, ...rest }) => {
  const { pushSnackbar } = useSnackbar();
  const { refetchUserInfo, userInfo } = useAuth();
  const [editUser] = useEditUser({
    onError: error => pushSnackbar({ variant: 'error', title: extractErrorMessage(error) }),
    onCompleted: () => {
      // Refetch user info if editing self
      if (user.id === userInfo.id) {
        refetchUserInfo();
      }

      pushSnackbar({ variant: 'success', title: 'User updated successfully!' });
    },
  });

  const initialValues = {
    id: user.id,
    email: user.email,
    familyName: user.familyName || '',
    givenName: user.givenName || '',
  };

  const submitToServer = async (values: UserFormValues) => {
    // optimistically hide the sidesheet
    onClose();

    await editUser({
      optimisticResponse: () => ({
        updateUser: {
          __typename: 'User',
          ...user,
          ...values,
        },
      }),
      variables: {
        input: {
          id: values.id,
          email: values.email,
          familyName: values.familyName,
          givenName: values.givenName,
        },
      },
    });
  };

  return (
    <SideSheet aria-labelledby="sidesheet-title" onClose={onClose} {...rest}>
      <Box width={425} m="auto">
        <Heading pt={1} pb={8} id="sidesheet-title">
          Edit Profile
        </Heading>
        <UserForm initialValues={initialValues} onSubmit={submitToServer} />
      </Box>
    </SideSheet>
  );
};

export default EditUserSidesheet;
