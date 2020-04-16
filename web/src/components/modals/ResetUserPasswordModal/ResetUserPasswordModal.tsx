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
import { useSnackbar } from 'pouncejs';
import { User } from 'Generated/schema';
import { ListUsersDocument } from 'Pages/Users';
import { getOperationName } from '@apollo/client/utilities/graphql/getFromAST';
import ConfirmModal from 'Components/modals/ConfirmModal';
import useModal from 'Hooks/useModal';
import { useResetUserPassword } from './graphql/resetUserPassword.generated';

export interface ResetUserPasswordProps {
  user: User;
}

const ResetUserPasswordModal: React.FC<ResetUserPasswordProps> = ({ user }) => {
  const { pushSnackbar } = useSnackbar();
  const { hideModal } = useModal();
  const userDisplayName = `${user.givenName} ${user.familyName}` || user.id;
  const [resetUserPassword, { loading }] = useResetUserPassword({
    variables: {
      id: user.id,
    },
    awaitRefetchQueries: true,
    refetchQueries: [getOperationName(ListUsersDocument)],
    onCompleted: () => {
      hideModal();
      pushSnackbar({
        variant: 'success',
        title: `Successfully forced a password change for ${userDisplayName}`,
      });
    },
    onError: () => {
      hideModal();
      pushSnackbar({ variant: 'error', title: `Failed to reset password for ${userDisplayName}` });
    },
  });

  return (
    <ConfirmModal
      onConfirm={resetUserPassword}
      onClose={hideModal}
      loading={loading}
      title={`Force a password change for ${userDisplayName}`}
      subtitle={`Are you sure you want to reset password for ${userDisplayName}?`}
    />
  );
};

export default ResetUserPasswordModal;
