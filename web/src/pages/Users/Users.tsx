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
import { Box, Button, Flex, Icon } from 'pouncejs';
import useSidesheet from 'Hooks/useSidesheet';
import { SIDESHEETS } from 'Components/utils/Sidesheet';
import ErrorBoundary from 'Components/ErrorBoundary';
import ListUsers from './ListUsers';

const UsersPage: React.FC = () => {
  const { showSidesheet } = useSidesheet();

  return (
    <Box mb={6}>
      <Flex justify="flex-end">
        <Button
          size="large"
          variant="primary"
          onClick={() => showSidesheet({ sidesheet: SIDESHEETS.USER_INVITATION })}
          mb={8}
        >
          <Flex align="center">
            <Icon type="add-user" size="small" mr={2} />
            Invite User
          </Flex>
        </Button>
      </Flex>
      <ErrorBoundary>
        <ListUsers />
      </ErrorBoundary>
    </Box>
  );
};

export default UsersPage;
