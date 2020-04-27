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
import urls from 'Source/urls';
import { Button, Dropdown, Flex, Icon, MenuItem } from 'pouncejs';
import useRouter from 'Hooks/useRouter';
import useSidesheet from 'Hooks/useSidesheet';
import { SIDESHEETS } from 'Components/utils/Sidesheet';

const CreateButton: React.FC = () => {
  const { history } = useRouter();
  const { showSidesheet } = useSidesheet();

  return (
    <Dropdown
      width={1}
      trigger={
        <Button size="large" variant="primary" as="div">
          <Flex>
            <Icon type="add" size="small" mr={2} />
            Create new
          </Flex>
        </Button>
      }
    >
      <Dropdown.Item onSelect={() => history.push(urls.logAnalysis.rules.create())}>
        <MenuItem variant="default">Single</MenuItem>
      </Dropdown.Item>
      <Dropdown.Item
        onSelect={() =>
          showSidesheet({
            sidesheet: SIDESHEETS.POLICY_BULK_UPLOAD,
            props: { type: 'rule' },
          })
        }
      >
        <MenuItem variant="default">Bulk Upload</MenuItem>
      </Dropdown.Item>
    </Dropdown>
  );
};

export default CreateButton;
