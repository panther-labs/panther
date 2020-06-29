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
import { Card, Box, Heading, Flex, Text, Dropdown, Icon, IconButton, MenuItem } from 'pouncejs';
import { getElapsedTime } from 'Helpers/utils';
import useRouter from 'Hooks/useRouter';
import useModal from 'Hooks/useModal';
import { GlobalPythonModuleTeaser } from 'Source/graphql/fragments/GlobalPythonModuleTeaser.generated';
import urls from 'Source/urls';
import { MODALS } from 'Components/utils/Modal';

interface GlobalItemProps {
  globalPythonModule: GlobalPythonModuleTeaser;
}

const GlobalPythonModuleItem: React.FC<GlobalItemProps> = ({ globalPythonModule }) => {
  const { showModal } = useModal();
  const { history } = useRouter();

  const lastModifiedTime = Math.floor(new Date(globalPythonModule.lastModified).getTime() / 1000);
  return (
    <Card p={9} key={globalPythonModule.id}>
      <Flex align="flex-start" justify="space-between">
        <Box>
          <Heading size="medium" color="grey500" mb={2}>
            {globalPythonModule.id}
          </Heading>
          <Text size="small" color="grey200">
            Last updated {getElapsedTime(lastModifiedTime)}
          </Text>
        </Box>
        <Dropdown
          position="relative"
          trigger={
            <IconButton as="div" variant="default" my={-2}>
              <Icon type="more" size="small" />
            </IconButton>
          }
        >
          <Dropdown.Item
            onSelect={() =>
              history.push(urls.settings.globalPythonModules.edit(globalPythonModule.id))
            }
          >
            <MenuItem variant="default">Edit</MenuItem>
          </Dropdown.Item>
          <Dropdown.Item
            onSelect={() =>
              showModal({
                modal: MODALS.DELETE_GLOBAL_PYTHON_MODULE,
                props: { globalPythonModule },
              })
            }
          >
            <MenuItem variant="default">Delete</MenuItem>
          </Dropdown.Item>
        </Dropdown>
      </Flex>
    </Card>
  );
};

export default React.memo(GlobalPythonModuleItem);
