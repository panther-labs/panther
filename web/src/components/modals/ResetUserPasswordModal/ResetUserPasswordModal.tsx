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
import { ListUsersDocument } from 'Pages/Users';
import { getOperationName } from '@apollo/client/utilities/graphql/getFromAST';
import BaseConfirmModal from 'Components/modals/BaseConfirmModal';
import { useResetUserPassword } from './graphql/resetUserPassword.generated';

export interface ResetUserPasswordProps {
  user: User;
}

const ResetUserPasswordModal: React.FC<ResetUserPasswordProps> = ({ user }) => {
  const userDisplayName = `${user.givenName} ${user.familyName}` || user.id;
  const mutation = useResetUserPassword({
    variables: {
      id: user.id,
    },
    awaitRefetchQueries: true,
    refetchQueries: [getOperationName(ListUsersDocument)],
  });
  return (
    <BaseConfirmModal
      mutation={mutation}
      title={`Force a password change for ${userDisplayName}`}
      subtitle={`Are you sure you want to reset password for ${userDisplayName}?`}
      onSuccessMsg={`Successfully forced a password change for ${userDisplayName}`}
      onErrorMsg={`Failed to reset password for ${userDisplayName}`}
    />
  );
};

export default ResetUserPasswordModal;
