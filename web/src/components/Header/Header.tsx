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
import {
  Flex,
  Icon,
  Dropdown,
  DropdownMenu,
  DropdownItem,
  DropdownButton,
  AbstractButton,
} from 'pouncejs';
import useAuth from 'Hooks/useAuth';
import useSidesheet from 'Hooks/useSidesheet';
import { SIDESHEETS } from 'Components/utils/Sidesheet';

const Header = () => {
  const { userInfo, signOut } = useAuth();
  const { showSidesheet } = useSidesheet();

  return (
    <Flex as="header" width={1} align="center" justify="space-between" py={10}>
      <Breadcrumbs />

      <Dropdown>
        <DropdownButton
          as={AbstractButton}
          flex="0 0 auto"
          size="small"
          variant="default"
          my="auto"
        >
          <Flex
            align="center"
            fontSize="medium"
            borderRadius="pill"
            backgroundColor="navyblue-500"
            py={2}
            px={4}
          >
            <Icon type="user" size="small" mr={2} borderRadius="circle" color="white" />
            {userInfo &&
              (userInfo.givenName && userInfo.familyName
                ? `${userInfo.givenName} ${userInfo.familyName[0]}.`
                : userInfo.email.split('@')[0])}
          </Flex>
        </DropdownButton>
        <DropdownMenu alignment="match-width">
          <DropdownItem onSelect={() => showSidesheet({ sidesheet: SIDESHEETS.EDIT_ACCOUNT })}>
            Edit Profile
          </DropdownItem>
          <DropdownItem onSelect={() => signOut({ global: true, onError: alert })}>
            Logout
          </DropdownItem>
        </DropdownMenu>
      </Dropdown>
    </Flex>
  );
};

export default Header;
