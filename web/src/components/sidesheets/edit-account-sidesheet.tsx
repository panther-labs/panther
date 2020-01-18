/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

import { Box, Heading, SideSheet } from 'pouncejs';
import EditProfileForm from 'Components/forms/edit-profile-form';
import ChangePasswordForm from 'Components/forms/change-password-form';
import React from 'react';
import useSidesheet from 'Hooks/useSidesheet';

const EditAccountSidesheet: React.FC = () => {
  const { hideSidesheet } = useSidesheet();
  return (
    <SideSheet open onClose={hideSidesheet}>
      <Box mx={10} mb={10}>
        <Heading pt={1} pb={8} size="medium">
          Edit Profile
        </Heading>
        <EditProfileForm onSuccess={hideSidesheet} />
      </Box>
      <Box borderTop="1px solid" borderColor="grey100" mx={10}>
        <Heading py={8} size="medium">
          Account Security
        </Heading>
        <ChangePasswordForm />
      </Box>
    </SideSheet>
  );
};

export default EditAccountSidesheet;
