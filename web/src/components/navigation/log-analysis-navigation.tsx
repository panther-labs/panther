import React from 'react';
import { Box, Flex } from 'pouncejs';
import RoleRestrictedAccess from 'Components/role-restricted-access';
import { ADMIN_ROLES_ARRAY } from 'Source/constants';
import urls from 'Source/urls';
import NavLink from './nav-link';

const LogAnalysisNavigation: React.FC = () => {
  return (
    <Box width={205} height="100%">
      <Flex flexDirection="column" mt="35vh" is="ul">
        <RoleRestrictedAccess allowedRoles={ADMIN_ROLES_ARRAY}>
          <Flex is="li">
            <NavLink icon="settings-alt" to={urls.logAnalysis.overview()} label="Overview" />
          </Flex>
          <Flex is="li">
            <NavLink icon="organization" to={urls.logAnalysis.rules.list()} label="Rules" />
          </Flex>
        </RoleRestrictedAccess>
        <Flex is="li">
          <NavLink icon="infra-source" to={urls.logAnalysis.alerts.list()} label="Alerts" />
        </Flex>
        <Flex is="li">
          <NavLink icon="output" to={urls.logAnalysis.sources.list()} label="Sources" />
        </Flex>
      </Flex>
    </Box>
  );
};

export default LogAnalysisNavigation;
