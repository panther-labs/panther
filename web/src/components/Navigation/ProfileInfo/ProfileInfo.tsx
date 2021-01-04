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
  Popover,
  PopoverTrigger,
  PopoverContent,
  Divider,
  Box,
  Text,
  Link,
  AbstractButton,
  Flex,
  Img,
  Card,
} from 'pouncejs';
import useAuth from 'Hooks/useAuth';
import { UserInfo } from 'Components/utils/AuthContext';
import { getUserDisplayName } from 'Helpers/utils';
import PantherIcon from 'Assets/panther-minimal-logo.svg';
import { pantherConfig } from 'Source/config';
import { MODALS } from 'Components/utils/Modal';
import useModal from 'Hooks/useModal';

const DEFAULT_INITIALS = '??';

const getUserName = (userInfo?: UserInfo) => {
  if (userInfo.givenName && userInfo.familyName) {
    return `${userInfo.givenName[0]}. ${userInfo.familyName}`;
  }
  if (userInfo.givenName) {
    return userInfo.givenName;
  }
  return userInfo.email;
};

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
    <Popover>
      {({ isOpen, close: closePopover }) => (
        <React.Fragment>
          <PopoverTrigger as={AbstractButton} aria-label="Toggle User Menu" width="100%">
            <Flex spacing={2} align="center">
              <Box
                width={40}
                display="flex"
                transition="background-color 0.1s linear"
                borderRadius="circle"
                justifyContent="center"
                alignItems="center"
                fontSize="small"
                fontWeight="bold"
                height={40}
                backgroundColor={isOpen ? 'violet-400' : 'violet-500'}
                flexShrink={0}
                _hover={{ backgroundColor: 'violet-400' }}
              >
                {getUserInitials(userInfo).toUpperCase()}
              </Box>
              <Box fontWeight="bold" truncated>
                {getUserName(userInfo)}
              </Box>
            </Flex>
          </PopoverTrigger>
          <PopoverContent alignment="right-bottom">
            <Card
              mx={20}
              my={-12}
              shadow="dark300"
              minWidth={240}
              fontSize="medium"
              overflow="hidden"
            >
              <Box p={6}>
                <Text>{getUserDisplayName(userInfo)}</Text>
                <Link external href={`mailto:${userInfo.email}`}>
                  {userInfo.email}
                </Link>
                <Divider mt={6} mb={3} color="navyblue-200" />
                <Box mb={2} mx={-2}>
                  <AbstractButton
                    p={2}
                    onClick={() => {
                      showModal({ modal: MODALS.EDIT_PROFILE_SETTINGS });
                      closePopover();
                    }}
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
                <Img
                  src={PantherIcon}
                  alt="Panther logo"
                  nativeWidth={16}
                  nativeHeight={16}
                  mr={2}
                />
                Panther&nbsp;<b>{pantherConfig.PANTHER_VERSION}</b>
              </Flex>
            </Card>
          </PopoverContent>
        </React.Fragment>
      )}
    </Popover>
  );
};

export default ProfileIcon;
