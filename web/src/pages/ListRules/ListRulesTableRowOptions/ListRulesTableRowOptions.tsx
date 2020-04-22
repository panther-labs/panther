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
import { Dropdown, Icon, IconButton, MenuItem, Box } from 'pouncejs';
import useRouter from 'Hooks/useRouter';
import { RuleSummary } from 'Generated/schema';
import urls from 'Source/urls';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/Modal';

interface ListPoliciesTableRowOptionsProps {
  rule: RuleSummary;
}

const ListRulesTableRowOptions: React.FC<ListPoliciesTableRowOptionsProps> = ({ rule }) => {
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
          <IconButton as="div" variant="default" my={-2}>
            <Icon type="more" size="small" />
          </IconButton>
        }
      >
        <Dropdown.Item onSelect={() => history.push(urls.logAnalysis.rules.edit(rule.id))}>
          <MenuItem variant="default">Edit</MenuItem>
        </Dropdown.Item>
        <Dropdown.Item
          onSelect={() =>
            showModal({
              modal: MODALS.DELETE_RULE,
              props: { rule },
            })
          }
        >
          <MenuItem variant="default">Delete</MenuItem>
        </Dropdown.Item>
      </Dropdown>
    </Box>
  );
};

export default React.memo(ListRulesTableRowOptions);
