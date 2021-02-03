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

import React from 'react';
import { ModalProps, useSnackbar } from 'pouncejs';
import { ListUsersDocument } from 'Pages/Users';
import { getOperationName } from 'apollo-utilities';
import ConfirmModal from 'Components/modals/ConfirmModal';
import { UserDetails } from 'Source/graphql/fragments/UserDetails.generated';
import { MessageActionEnum } from 'Generated/schema';
import { useInviteUser } from './graphql/inviteUser.generated';

export interface ReinviteUserProps extends ModalProps {
  user: UserDetails;
}

const ResetUserPasswordModal: React.FC<ReinviteUserProps> = ({ user, onClose, ...rest }) => {
  const { pushSnackbar } = useSnackbar();
  const userDisplayName = `${user.givenName} ${user.familyName}` || user.id;
  const [resetUserPassword, { loading }] = useInviteUser({
    variables: {
      input: {
        email: user.email,
        familyName: user.familyName,
        givenName: user.givenName,
        messageAction: MessageActionEnum.Resend,
      },
    },
    awaitRefetchQueries: true,
    refetchQueries: [getOperationName(ListUsersDocument)],
    onCompleted: () => {
      onClose();
      pushSnackbar({
        variant: 'success',
        title: `Successfully reinvited user ${userDisplayName}`,
      });
    },
    onError: () => {
      onClose();
      pushSnackbar({ variant: 'error', title: `Failed to reinvite user ${userDisplayName}` });
    },
  });

  return (
    <ConfirmModal
      onConfirm={resetUserPassword}
      onClose={onClose}
      loading={loading}
      title={`Reinvite user ${userDisplayName}`}
      subtitle={`Are you sure you want to reinvite user ${userDisplayName}?`}
      {...rest}
    />
  );
};

export default ResetUserPasswordModal;
