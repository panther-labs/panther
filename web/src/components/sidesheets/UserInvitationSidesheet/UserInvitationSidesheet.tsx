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

import {
  Box,
  Heading,
  Text,
  SideSheet,
  useSnackbar,
  SideSheetProps,
  FormHelperText,
} from 'pouncejs';
import React from 'react';
import { extractErrorMessage } from 'Helpers/utils';
import UserForm from 'Components/forms/UserForm';
import { EventEnum, SrcEnum, trackEvent } from 'Helpers/analytics';
import { useInviteUser } from './graphql/inviteUser.generated';

const initialValues = {
  email: '',
  familyName: '',
  givenName: '',
};

const UserInvitationSidesheet: React.FC<SideSheetProps> = props => {
  const { pushSnackbar } = useSnackbar();
  const [inviteUser] = useInviteUser({
    update: (cache, { data: { inviteUser: newUser } }) => {
      cache.modify('ROOT_QUERY', {
        users(existingData, { toReference }) {
          return [toReference(newUser), ...existingData];
        },
      });
    },
    onCompleted: () => {
      props.onClose();
      trackEvent({ event: EventEnum.InvitedUser, src: SrcEnum.Users });
      pushSnackbar({ variant: 'success', title: 'User invited successfully' });
    },
    onError: error => pushSnackbar({ variant: 'error', title: extractErrorMessage(error) }),
  });

  return (
    <SideSheet
      aria-labelledby="sidesheet-title"
      aria-describedby="sidesheet-description role-disclaimer"
      {...props}
    >
      <Box width={425} m="auto">
        <Heading mb={8} id="sidesheet-title">
          Invite User
        </Heading>
        <Text color="gray-300" mb={8} id="sidesheet-description">
          By inviting users to join your organization, they will receive an email with temporary
          credentials that they can use to sign in to the platform
        </Text>
        <UserForm
          initialValues={initialValues}
          onSubmit={values => inviteUser({ variables: { input: values } })}
        />
        <FormHelperText id="role-disclaimer" textAlign="center" mt={4}>
          All users in the Open-Source version of Panther are admins in the system.
          <br />
          Role-based access is a feature available in the Enterprise version.
        </FormHelperText>
      </Box>
    </SideSheet>
  );
};

export default UserInvitationSidesheet;
