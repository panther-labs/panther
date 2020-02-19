import React from 'react';
import { Badge, Box, Flex, Heading } from 'pouncejs';
import urls from 'Source/urls';
import NavLink from './nav-link';

const LogAnalysisNavigation: React.FC = () => {
  return (
    <Box>
      <Heading size="medium" textAlign="center" mt={10} mb={5}>
        <b>LOG ANALYSIS</b>
      </Heading>
      <Flex flexDirection="column" is="ul">
        <Flex is="li" position="relative">
          <NavLink icon="dashboard-alt" to={urls.logAnalysis.overview()} label="Overview" />
          <Box position="absolute" right="10px" top="23px">
            <Badge color="blue">Coming Soon</Badge>
          </Box>
        </Flex>
        <Flex is="li">
          <NavLink icon="rule" to={urls.logAnalysis.rules.list()} label="Rules" />
        </Flex>
        <Flex is="li">
          <NavLink icon="alert" to={urls.logAnalysis.alerts.list()} label="Alerts" />
        </Flex>
        <Flex is="li">
          <NavLink icon="log-source" to={urls.logAnalysis.sources.list()} label="Sources" />
        </Flex>
      </Flex>
    </Box>
  );
};

export default LogAnalysisNavigation;
