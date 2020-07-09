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
import {
  useSnackbar,
  Dropdown,
  DropdownButton,
  AbstractButton,
  DropdownMenu,
  DropdownItem,
} from 'pouncejs';
import { AlertStatusesEnum } from 'Generated/schema';
import AlertStatusBadge from 'Components/AlertStatusBadge';
import { useUpdateAlert } from './graphql/updateAlert.generated';

export interface UpdateAlertMenuProps {
  status: AlertStatusesEnum;
  alertId: string;
}

const UpdateAlertMenu: React.FC<UpdateAlertMenuProps> = ({ status, alertId }) => {
  const { pushSnackbar } = useSnackbar();

  const [updateAlert] = useUpdateAlert({
    variables: {
      input: {
        status,
        alertId,
      },
    },
    onCompleted: () => {
      pushSnackbar({
        variant: 'success',
        title: `Successfully updated alert`,
      });
    },
    onError: error => {
      pushSnackbar({
        variant: 'error',
        title: `Failed to update alert ${error}`,
      });
    },
  });

  const availableStatusesEntries = Object.entries(AlertStatusesEnum);

  return (
    <Dropdown>
      <DropdownButton as={AbstractButton} aria-label="Status Options">
        <AlertStatusBadge status={status} />
      </DropdownButton>
      <DropdownMenu>
        {availableStatusesEntries.map(([statusKey, statusVal], index) => (
          <DropdownItem
            key={index}
            disabled={status === statusVal}
            onSelect={() => updateAlert({ variables: { input: { status, alertId } } })}
          >
            {statusKey}
          </DropdownItem>
        ))}
      </DropdownMenu>
    </Dropdown>
  );
};

export default UpdateAlertMenu;
