import React from 'react';
import { Box, Flex, Heading } from 'pouncejs';
import urls from 'Source/urls';
import NavLink from './nav-link';

const ComplianceNavigation: React.FC = () => {
  return (
    <Box>
      <Heading size="medium" textAlign="center" mt={10} mb={5}>
        <b>CLOUD SECURITY</b>
      </Heading>
      <Flex flexDirection="column" is="ul">
        <Flex is="li">
          <NavLink icon="dashboard-alt" to={urls.compliance.overview()} label="Overview" />
        </Flex>
        <Flex is="li">
          <NavLink icon="policy" to={urls.compliance.policies.list()} label="Policies" />
        </Flex>
        <Flex is="li">
          <NavLink icon="resource" to={urls.compliance.resources.list()} label="Resources" />
        </Flex>
        <Flex is="li">
          <NavLink icon="infra-source" to={urls.compliance.sources.list()} label="Sources" />
        </Flex>
      </Flex>
    </Box>
  );
};

export default ComplianceNavigation;
