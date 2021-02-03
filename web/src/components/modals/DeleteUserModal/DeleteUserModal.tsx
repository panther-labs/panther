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
import useAuth from 'Hooks/useAuth';
import { UserDetails } from 'Source/graphql/fragments/UserDetails.generated';
import { getUserDisplayName } from 'Helpers/utils';
import { useDeleteUser } from './graphql/deleteUser.generated';
import OptimisticConfirmModal from '../OptimisticConfirmModal';

export interface DeleteUserModalProps extends ModalProps {
  user: UserDetails;
}

const DeleteUserModal: React.FC<DeleteUserModalProps> = ({ user, ...rest }) => {
  const { signOut, userInfo } = useAuth();
  const { pushSnackbar } = useSnackbar();

  const userDisplayName = getUserDisplayName(user);
  const [deleteUser] = useDeleteUser({
    variables: {
      id: user.id,
    },
    optimisticResponse: {
      deleteUser: true,
    },
    update: async cache => {
      cache.modify('ROOT_QUERY', {
        users: (data, helpers) => {
          const userRef = helpers.toReference(user);
          return data.filter(u => u.__ref !== userRef.__ref);
        },
      });
      cache.gc();
    },
    onCompleted: async () => {
      pushSnackbar({
        variant: 'success',
        title: `Successfully deleted user: ${userDisplayName}`,
      });
      // Checking if user deleted is the same as the user signed in
      if (userInfo.id === user.id) {
        await signOut({ global: true });
      }
    },
    onError: () => {
      pushSnackbar({
        variant: 'error',
        title: `Failed to delete user: ${userDisplayName}`,
      });
    },
  });

  return (
    <OptimisticConfirmModal
      title={`Delete ${userDisplayName}`}
      subtitle={`Are you sure you want to delete ${userDisplayName}?`}
      onConfirm={deleteUser}
      {...rest}
    />
  );
};

export default DeleteUserModal;
