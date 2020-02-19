import React from 'react';
import { Box, Flex, Heading } from 'pouncejs';
import RoleRestrictedAccess from 'Components/role-restricted-access';
import { ADMIN_ROLES_ARRAY } from 'Source/constants';
import urls from 'Source/urls';
import NavLink from './nav-link';

const SettingsNavigation: React.FC = () => {
  return (
    <Box>
      <Heading size="medium" textAlign="center" mt={10} mb={5}>
        <b>SETTINGS</b>
      </Heading>
      <Flex flexDirection="column" is="ul">
        <RoleRestrictedAccess allowedRoles={ADMIN_ROLES_ARRAY}>
          <Flex is="li">
            <NavLink icon="settings-alt" to={urls.account.settings.general()} label="General" />
          </Flex>
          <Flex is="li">
            <NavLink icon="organization" to={urls.account.settings.users()} label="Users" />
          </Flex>
        </RoleRestrictedAccess>
        <Flex is="li">
          <NavLink icon="output" to={urls.account.settings.destinations()} label="Destinations" />
        </Flex>
      </Flex>
    </Box>
  );
};

export default SettingsNavigation;
