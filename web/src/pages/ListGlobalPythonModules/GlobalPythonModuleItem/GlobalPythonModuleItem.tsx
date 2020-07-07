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
  Card,
  Box,
  Heading,
  Flex,
  Dropdown,
  IconButton,
  DropdownButton,
  DropdownMenu,
  DropdownLink,
  DropdownItem,
  Link,
} from 'pouncejs';
import { getElapsedTime } from 'Helpers/utils';
import useModal from 'Hooks/useModal';
import { GlobalPythonModuleTeaser } from 'Source/graphql/fragments/GlobalPythonModuleTeaser.generated';
import urls from 'Source/urls';
import { MODALS } from 'Components/utils/Modal';
import { Link as RRLink } from 'react-router-dom';

interface GlobalItemProps {
  globalPythonModule: GlobalPythonModuleTeaser;
}

const GlobalPythonModuleItem: React.FC<GlobalItemProps> = ({ globalPythonModule }) => {
  const { showModal } = useModal();

  const lastModifiedTime = Math.floor(new Date(globalPythonModule.lastModified).getTime() / 1000);
  return (
    <Card variant="dark" p={6} key={globalPythonModule.id}>
      <Flex align="flex-start" justify="space-between">
        <Box>
          <Heading as="h4" size="x-small">
            <Link
              as={RRLink}
              to={urls.settings.globalPythonModules.edit(globalPythonModule.id)}
              py={1}
            >
              {globalPythonModule.id}
            </Link>
          </Heading>
          <Box as="time" fontSize="small" color="gray-300">
            Last updated {getElapsedTime(lastModifiedTime)}
          </Box>
        </Box>
        <Dropdown>
          <DropdownButton
            as={IconButton}
            icon="more"
            variant="ghost"
            size="small"
            aria-label="Global Python Module Options"
          />
          <DropdownMenu>
            <DropdownLink
              as={RRLink}
              to={urls.settings.globalPythonModules.edit(globalPythonModule.id)}
            >
              Edit
            </DropdownLink>
            <DropdownItem
              onSelect={() => {
                showModal({
                  modal: MODALS.DELETE_GLOBAL_PYTHON_MODULE,
                  props: { globalPythonModule },
                });
              }}
            >
              Delete
            </DropdownItem>
          </DropdownMenu>
        </Dropdown>
      </Flex>
    </Card>
  );
};

export default React.memo(GlobalPythonModuleItem);
