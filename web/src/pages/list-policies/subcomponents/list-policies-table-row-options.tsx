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
import { Dropdown, Icon, IconButton, MenuItem, Box } from 'pouncejs';
import useRouter from 'Hooks/useRouter';
import { PolicySummary } from 'Generated/schema';
import urls from 'Source/urls';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/modal-context';

interface ListPoliciesTableRowOptionsProps {
  policy: PolicySummary;
}

const ListPoliciesTableRowOptions: React.FC<ListPoliciesTableRowOptionsProps> = ({ policy }) => {
  const { history } = useRouter();
  const { showModal } = useModal();

  // @HELP_WANTED
  // The wrapping `<Box>` is needed because of a special reason. You see, the trigger of this
  // Dropdown is added on each row of a table whose rows are clickable. Thus we don't wanna trigger
  // a click on the row each time the Dropdown trigger is clicked. If we had added the
  // `stopPropagation()` on the trigger itself, then the Dropdown wouldn't open.
  // We perhaps can find a better solution to his problem
  return (
    <Box onClick={e => e.stopPropagation()}>
      <Dropdown
        trigger={
          <IconButton is="div" variant="default" my={-2}>
            <Icon type="more" size="small" />
          </IconButton>
        }
      >
        <Dropdown.Item onSelect={() => history.push(urls.policies.edit(policy.id))}>
          <MenuItem variant="default">Edit</MenuItem>
        </Dropdown.Item>
        <Dropdown.Item
          onSelect={() =>
            showModal({
              modal: MODALS.DELETE_POLICY,
              props: { policy },
            })
          }
        >
          <MenuItem variant="default">Delete</MenuItem>
        </Dropdown.Item>
      </Dropdown>
    </Box>
  );
};

export default React.memo(ListPoliciesTableRowOptions);
