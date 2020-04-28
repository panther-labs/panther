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
import Breadcrumbs from 'Components/Breadcrumbs';
import { Button, Flex, Icon, IconButton, Text, Dropdown, MenuItem, Box } from 'pouncejs';
import useAuth from 'Hooks/useAuth';
import useSidesheet from 'Hooks/useSidesheet';
import { SIDESHEETS } from 'Components/utils/Sidesheet';

const Header = () => {
  const { userInfo, signOut } = useAuth();
  const { showSidesheet } = useSidesheet();

  const userButton = React.useMemo(
    () => (
      <Box flex="0 0 auto">
        <Button size="small" variant="default" my="auto" as="div">
          <Flex align="center">
            <Icon
              type="user"
              size="small"
              mr={2}
              borderRadius="circle"
              bg="grey200"
              color="white"
            />
            {userInfo && (
              <Text size="medium">
                {userInfo.given_name && userInfo.family_name
                  ? `${userInfo.given_name} ${userInfo.family_name[0]}.`
                  : userInfo.email.split('@')[0]}
              </Text>
            )}
          </Flex>
        </Button>
      </Box>
    ),
    [userInfo]
  );

  return (
    <Flex width={1} borderBottom="1px solid" borderColor="grey100" py={8}>
      <Breadcrumbs />
      <IconButton variant="default" mr={6} ml="auto" flex="0 0 auto" arial-label="Notifications">
        <Icon size="small" type="notification" />
      </IconButton>
      <Dropdown trigger={userButton} minWidth="100%">
        <Dropdown.Item onSelect={() => showSidesheet({ sidesheet: SIDESHEETS.EDIT_ACCOUNT })}>
          <MenuItem variant="default">Edit Profile</MenuItem>
        </Dropdown.Item>
        <Dropdown.Item onSelect={() => signOut({ onError: alert })}>
          <MenuItem variant="default" m={0}>
            Logout
          </MenuItem>
        </Dropdown.Item>
      </Dropdown>
    </Flex>
  );
};

export default Header;
