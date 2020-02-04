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
import { Dropdown, Icon, IconButton, MenuItem } from 'pouncejs';
import { User } from 'Generated/schema';
import { ADMIN_ROLES_ARRAY } from 'Source/constants';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/modal-context';
import RoleRestrictedAccess from 'Components/role-restricted-access';

interface ListUsersTableRowOptionsProps {
  user: User;
}

const ListUsersTableRowOptions: React.FC<ListUsersTableRowOptionsProps> = ({ user }) => {
  const { showModal } = useModal();

  return (
    <RoleRestrictedAccess allowedRoles={ADMIN_ROLES_ARRAY}>
      <Dropdown
        trigger={
          <IconButton is="div" variant="default" my={-2}>
            <Icon type="more" size="small" />
          </IconButton>
        }
      >
        <Dropdown.Item
          onSelect={() =>
            showModal({
              modal: MODALS.DELETE_USER,
              props: { user },
            })
          }
        >
          <MenuItem variant="default">Delete</MenuItem>
        </Dropdown.Item>
      </Dropdown>
    </RoleRestrictedAccess>
  );
};

export default React.memo(ListUsersTableRowOptions);
