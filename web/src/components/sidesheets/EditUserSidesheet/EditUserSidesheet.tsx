/**
 * A Cloud-Native SIEM for the Modern Security Team
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
import { Box, Heading, SideSheet, useSnackbar } from 'pouncejs';
import { User } from 'Generated/schema';
import { extractErrorMessage } from 'Helpers/utils';
import UserForm, { UserFormValues } from 'Components/forms/UserForm';
import useAuth from 'Hooks/useAuth';
import useSidesheet from 'Hooks/useSidesheet';
import { useEditUser } from './graphql/editUser.generated';

export interface EditUserSidesheetProps {
  user: User;
}

const EditUserSidesheet: React.FC<EditUserSidesheetProps> = ({ user }) => {
  const { pushSnackbar } = useSnackbar();
  const { hideSidesheet } = useSidesheet();
  const { refetchUserInfo, userInfo } = useAuth();
  const [editUser] = useEditUser({
    onError: error => pushSnackbar({ variant: 'error', title: extractErrorMessage(error) }),
    onCompleted: () => {
      // Refetch user info if editing self
      if (user.id === userInfo.sub) {
        refetchUserInfo();
      }
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
    hideSidesheet();

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
    <SideSheet open onClose={hideSidesheet}>
      <Box width={425} m="auto">
        <Heading pt={1} pb={8} size="medium">
          Edit Profile
        </Heading>
        <UserForm initialValues={initialValues} onSubmit={submitToServer} />
      </Box>
    </SideSheet>
  );
};

export default EditUserSidesheet;
