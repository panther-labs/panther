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

import { Box, Heading, Text, SideSheet, useSnackbar } from 'pouncejs';
import React from 'react';
import useSidesheet from 'Hooks/useSidesheet';
import { extractErrorMessage } from 'Helpers/utils';
import UserForm, { UserFormValues } from 'Components/forms/UserForm';
import { useInviteUser } from './graphql/inviteUser.generated';

const initialValues = {
  email: '',
  familyName: '',
  givenName: '',
};

const UserInvitationSidesheet: React.FC = () => {
  const { hideSidesheet } = useSidesheet();
  const { pushSnackbar } = useSnackbar();
  const [inviteUser] = useInviteUser({
    update: (cache, { data: { inviteUser: newUser } }) => {
      cache.modify({
        fields: {
          users(existingData, { toReference }) {
            return [toReference(newUser), ...existingData];
          },
        },
      });
    },
    onError: error => pushSnackbar({ variant: 'error', title: extractErrorMessage(error) }),
  });

  const submitToServer = async (values: UserFormValues) => {
    hideSidesheet();

    await inviteUser({
      // optimistically hide the sidesheet
      optimisticResponse: () => ({
        inviteUser: {
          id: '',
          createdAt: new Date().getTime() / 1000,
          status: 'FORCE_CHANGE_PASSWORD',
          __typename: 'User',
          ...values,
        },
      }),
      variables: {
        input: {
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
        <Heading size="medium" mb={8}>
          Invite User
        </Heading>
        <Text size="large" color="grey200" mb={8}>
          By inviting users to join your organization, they will receive an email with temporary
          credentials that they can use to sign in to the platform
        </Text>
        <UserForm initialValues={initialValues} onSubmit={submitToServer} />
        <Text size="small" color="grey300" textAlign="center" mt={6}>
          All users in the Open-Source version of Panther are admins in the system.
          <br />
          Role-based access is a feature available in the Enterprise version.
        </Text>
      </Box>
    </SideSheet>
  );
};

export default UserInvitationSidesheet;
