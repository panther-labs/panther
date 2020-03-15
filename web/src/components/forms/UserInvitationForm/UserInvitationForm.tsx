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
import { Alert, Box, useSnackbar } from 'pouncejs';
import { ListUsersDocument } from 'Pages/Users';
import { getOperationName } from '@apollo/client/utilities/graphql/getFromAST';
import { extractErrorMessage } from 'Helpers/utils';
import BaseUserForm from 'Components/forms/BaseUserForm';
import { useInviteUser } from './graphql/inviteUser.generated';

interface UserInvitationFormProps {
  onSuccess: () => void;
}

const initialValues = {
  email: '',
  familyName: '',
  givenName: '',
};

const UserInvitationForm: React.FC<UserInvitationFormProps> = ({ onSuccess }) => {
  const [inviteUser, { error: inviteUserError, data }] = useInviteUser();
  const { pushSnackbar } = useSnackbar();

  React.useEffect(() => {
    if (data) {
      pushSnackbar({ variant: 'success', title: `Successfully invited user` });
      onSuccess();
    }
  }, [data]);

  return (
    <Box>
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
      <BaseUserForm
        initialValues={initialValues}
        onSubmit={async values => {
          await inviteUser({
            variables: {
              input: {
                email: values.email,
                familyName: values.familyName,
                givenName: values.givenName,
              },
            },
            refetchQueries: [getOperationName(ListUsersDocument)],
          });
        }}
      />
    </Box>
  );
};

export default UserInvitationForm;
