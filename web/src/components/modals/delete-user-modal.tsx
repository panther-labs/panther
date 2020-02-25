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

import React from 'react';
import { User } from 'Generated/schema';

import { useMutation, gql } from '@apollo/client';
import { LIST_USERS } from 'Pages/users/subcomponents/list-users-table';
import { getOperationName } from '@apollo/client/utilities/graphql/getFromAST';
import BaseDeleteModal from 'Components/modals/base-delete-modal';
import useAuth from 'Hooks/useAuth';

const DELETE_USER = gql`
  mutation DeleteUser($id: ID!) {
    deleteUser(id: $id)
  }
`;

export interface DeleteUserModalProps {
  user: User;
}

const DeleteUserModal: React.FC<DeleteUserModalProps> = ({ user }) => {
  const { signOut, userInfo } = useAuth();
  // Checking if user deleted is the same as the user signed in
  const onSuccess = () => userInfo.sub === user.id && signOut();

  const userDisplayName = `${user.givenName} ${user.familyName}` || user.id;
  const mutation = useMutation<boolean, { id: string }>(DELETE_USER, {
    variables: {
      id: user.id,
    },
    awaitRefetchQueries: true,
    refetchQueries: [getOperationName(LIST_USERS)],
  });

  return (
    <BaseDeleteModal mutation={mutation} itemDisplayName={userDisplayName} onSuccess={onSuccess} />
  );
};

export default DeleteUserModal;
