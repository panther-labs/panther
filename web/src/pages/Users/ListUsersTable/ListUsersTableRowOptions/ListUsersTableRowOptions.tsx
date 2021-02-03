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
import { Dropdown, DropdownButton, DropdownItem, DropdownMenu, IconButton } from 'pouncejs';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/Modal';
import { SIDESHEETS } from 'Components/utils/Sidesheet';
import useSidesheet from 'Hooks/useSidesheet';
import { UserDetails } from 'Source/graphql/fragments/UserDetails.generated';

interface ListUsersTableRowOptionsProps {
  user: UserDetails;
}

const ListUsersTableRowOptions: React.FC<ListUsersTableRowOptionsProps> = ({ user }) => {
  const { showModal } = useModal();
  const { showSidesheet } = useSidesheet();

  return (
    <Dropdown>
      <DropdownButton
        as={IconButton}
        icon="more"
        variant="ghost"
        variantBorderStyle="circle"
        size="medium"
        aria-label="User Options"
      />
      <DropdownMenu>
        <DropdownItem
          onSelect={() => showSidesheet({ sidesheet: SIDESHEETS.EDIT_USER, props: { user } })}
        >
          Edit
        </DropdownItem>
        {user.status !== 'FORCE_CHANGE_PASSWORD' ? (
          <DropdownItem
            onSelect={() =>
              showModal({
                modal: MODALS.RESET_USER_PASS,
                props: { user },
              })
            }
          >
            Force password reset
          </DropdownItem>
        ) : (
          <DropdownItem
            onSelect={() =>
              showModal({
                modal: MODALS.REINVITE_USER,
                props: { user },
              })
            }
          >
            Reinvite user
          </DropdownItem>
        )}
        <DropdownItem
          onSelect={() =>
            showModal({
              modal: MODALS.DELETE_USER,
              props: { user },
            })
          }
        >
          Delete
        </DropdownItem>
      </DropdownMenu>
    </Dropdown>
  );
};

export default React.memo(ListUsersTableRowOptions);
