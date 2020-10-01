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
  Dropdown,
  DropdownButton,
  DropdownMenu,
  Divider,
  Box,
  Text,
  Link,
  AbstractButton,
  Flex,
  Img,
} from 'pouncejs';
import useAuth from 'Hooks/useAuth';
import { UserInfo } from 'Components/utils/AuthContext';
import { getUserDisplayName } from 'Helpers/utils';
import PantherIcon from 'Assets/panther-minimal-logo.svg';
import { STABLE_PANTHER_VERSION } from 'Source/constants';
import { MODALS } from 'Components/utils/Modal';
import useModal from 'Hooks/useModal';

const DEFAULT_INITIALS = '??';

const getUserInitials = (userInfo?: UserInfo) => {
  if (!userInfo) {
    return DEFAULT_INITIALS;
  }
  if (userInfo.givenName && userInfo.familyName) {
    return `${userInfo.givenName[0]}${userInfo.familyName[0]}`;
  }

  if (userInfo.givenName) {
    return userInfo.givenName.slice(0, 2);
  }

  if (userInfo.familyName) {
    return userInfo.familyName.slice(0, 2);
  }

  return userInfo.email.slice(0, 2);
};

const ProfileIcon: React.FC = () => {
  const { userInfo, signOut } = useAuth();
  const { showModal } = useModal();

  return (
    <Dropdown>
      {({ isExpanded }) => (
        <React.Fragment>
          <DropdownButton
            as={AbstractButton}
            display="flex"
            width={40}
            height={40}
            backgroundColor={isExpanded ? 'violet-400' : 'violet-500'}
            _hover={{ backgroundColor: 'violet-400' }}
            transition="background-color 0.1s linear"
            borderRadius="circle"
            justifyContent="center"
            alignItems="center"
            fontSize="small"
            fontWeight="bold"
            aria-label="Toggle User Menu"
          >
            {getUserInitials(userInfo).toUpperCase()}
          </DropdownButton>
          <DropdownMenu alignment="right" transform="translate(65px, -65px)">
            <Box p={6} minWidth={240} backgroundColor="navyblue-400" fontSize="medium">
              <Text>{getUserDisplayName(userInfo)}</Text>
              <Link external href={`mailto:${userInfo.email}`}>
                {userInfo.email}
              </Link>
              <Divider mt={6} mb={3} color="navyblue-200" />
              <Box mb={2} mx={-2}>
                <AbstractButton
                  p={2}
                  onClick={() => showModal({ modal: MODALS.EDIT_PROFILE_SETTINGS })}
                >
                  Profile Settings
                </AbstractButton>
              </Box>
              <Box mx={-2}>
                <AbstractButton p={2} onClick={() => signOut({ global: true, onError: alert })}>
                  Log Out
                </AbstractButton>
              </Box>
            </Box>
            <Flex
              as="footer"
              justify="center"
              backgroundColor="navyblue-600"
              p={3}
              mt={-2}
              fontSize="small"
              fontStyle="italic"
            >
              <Img src={PantherIcon} alt="Panther logo" nativeWidth={16} nativeHeight={16} mr={2} />
              Panther&nbsp;<b>{STABLE_PANTHER_VERSION}</b>
            </Flex>
          </DropdownMenu>
        </React.Fragment>
      )}
    </Dropdown>
  );
};

export default ProfileIcon;
