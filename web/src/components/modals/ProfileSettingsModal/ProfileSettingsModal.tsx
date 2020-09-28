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

import {
  Box,
  Modal,
  ModalProps,
  TabPanel,
  TabPanels,
  Tabs,
  TabList,
  Text,
  Link,
  Flex,
} from 'pouncejs';
import EditProfileForm from 'Components/forms/EditProfileForm';
import ChangePasswordForm from 'Components/forms/ChangePasswordForm';
import React from 'react';
import useAuth from 'Hooks/useAuth';
import { getUserDisplayName } from 'Helpers/utils';
import { BorderedTab, BorderTabDivider } from 'Components/BorderedTab';

const ProfileSettingsModal: React.FC<ModalProps> = ({ onClose, ...rest }) => {
  const { userInfo } = useAuth();
  return (
    <Modal showCloseButton aria-label="Profile & Account Settings" onClose={onClose} {...rest}>
      <Box width={450}>
        <Tabs>
          <Box mt={-8} mx={-6}>
            <TabList>
              <BorderedTab>Profile Settings</BorderedTab>
              <BorderedTab>Account Security</BorderedTab>
            </TabList>
            <BorderTabDivider />
          </Box>
          <Box px={8} mt={8}>
            <TabPanels>
              <TabPanel>
                <Flex as="section" direction="column" align="center" mb={6}>
                  <Text fontSize="small" color="gray-300" mb={3}>
                    logged in as
                  </Text>
                  <Text fontSize="medium">{getUserDisplayName(userInfo)}</Text>
                  <Link fontSize="medium" external href={`mailto:${userInfo.email}`}>
                    {userInfo.email}
                  </Link>
                </Flex>
                <EditProfileForm onSuccess={onClose} />
              </TabPanel>
              <TabPanel>
                <ChangePasswordForm onSuccess={onClose} />
              </TabPanel>
            </TabPanels>
          </Box>
        </Tabs>
      </Box>
    </Modal>
  );
};

export default ProfileSettingsModal;
