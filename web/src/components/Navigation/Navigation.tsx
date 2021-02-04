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
import { Box, Flex, Img, Icon, Link, Divider } from 'pouncejs';
import urls from 'Source/urls';
import { Link as RRLink } from 'react-router-dom';
import PantherLogo from 'Assets/panther-plain-logo.svg';
import { PANTHER_DOCS_LINK } from 'Source/constants';
import useRouter from 'Hooks/useRouter';
import { AlertStatusesEnum } from 'Generated/schema';
import NavLink from './NavLink';
import NavGroup from './NavGroup';
import ProfileInfo from './ProfileInfo';
import {
  SettingsNavigation,
  ComplianceNavigation,
  LogAnalysisNavigation,
} from './SecondaryNavigations';

const COMPLIANCE_NAV_KEY = 'compliance';
const LOG_ANALYSIS_NAV_KEY = 'logAnalysis';
const SETTINGS_NAV_KEY = 'settings';

type NavKeys = typeof COMPLIANCE_NAV_KEY | typeof LOG_ANALYSIS_NAV_KEY | typeof SETTINGS_NAV_KEY;

const Navigation = () => {
  const {
    location: { pathname },
  } = useRouter();

  // Normally we woulnd't be neeeding the code below in a separate function. It would just be inside
  // a `React.useEffect`. We add this here cause it's important to give React.useState the proper
  // initial value, so that the animation of the Navbar doesn't kick on the initial render. If it
  // wasn't for that, we wouldn't have "abstracted" this function here and we would just have an
  // initial value of `null` which would instantly be updated from the code in `React.useEffect`
  const getSecondaryNavKey = () => {
    const isCompliancePage = pathname.includes(urls.compliance.home());
    const isLogAnalysisPage =
      pathname.includes(urls.logAnalysis.home()) &&
      !pathname.includes(urls.logAnalysis.alerts.list());
    const isSettingsPage = pathname.includes(urls.settings.home());

    if (isCompliancePage) {
      return COMPLIANCE_NAV_KEY;
    }
    if (isLogAnalysisPage) {
      return LOG_ANALYSIS_NAV_KEY;
    }
    if (isSettingsPage) {
      return SETTINGS_NAV_KEY;
    }
    return null;
  };

  const [secondaryNav, setSecondaryNav] = React.useState<NavKeys>(getSecondaryNavKey());

  React.useEffect(() => {
    setSecondaryNav(getSecondaryNavKey());
  }, [pathname]);

  const isComplianceNavigationActive = secondaryNav === COMPLIANCE_NAV_KEY;
  const isLogAnalysisNavigationActive = secondaryNav === LOG_ANALYSIS_NAV_KEY;
  const isSettingsNavigationActive = secondaryNav === SETTINGS_NAV_KEY;

  return (
    <Flex
      as="aside"
      boxShadow="dark50"
      position="sticky"
      top={0}
      zIndex={10}
      height="100vh"
      backgroundColor="navyblue-700"
    >
      <Flex as="nav" direction="column" width={220} height="100%" aria-label="Main" pb={2}>
        <Box as={RRLink} to="/" px={4} pb={3} pt={8}>
          <Img
            src={PantherLogo}
            alt="Panther logo"
            nativeWidth="auto"
            nativeHeight={32}
            display="block"
          />
        </Box>
        <Flex direction="column" as="ul" flex="1 0 auto" px={4}>
          <Divider width="100%" color="navyblue-300" />
          <Box as="li" mb={2}>
            <NavLink
              icon="alert-circle"
              to={`${urls.logAnalysis.alerts.list()}?status[]=${AlertStatusesEnum.Open}&status[]=${
                AlertStatusesEnum.Triaged
              }`}
              label="Alerts"
            />
          </Box>
          <Box as="li" mb={2}>
            <NavLink
              icon="detection"
              to={`${urls.detections.list()}?page=1&sortBy=lastModified&sortDir=descending`}
              label="Detections"
            />
          </Box>

          <Box as="li" mb={2}>
            <NavGroup
              active={isLogAnalysisNavigationActive}
              icon="log-analysis"
              label="Log Analysis"
              onSelect={() =>
                setSecondaryNav(isLogAnalysisNavigationActive ? null : LOG_ANALYSIS_NAV_KEY)
              }
            >
              <LogAnalysisNavigation />
            </NavGroup>
          </Box>
          <Box as="li" mb={2}>
            <NavGroup
              active={isComplianceNavigationActive}
              icon="cloud-security"
              label="Cloud Security"
              onSelect={() =>
                setSecondaryNav(isComplianceNavigationActive ? null : COMPLIANCE_NAV_KEY)
              }
            >
              <ComplianceNavigation />
            </NavGroup>
          </Box>
          <Box as="li" mb={2}>
            <NavGroup
              active={isSettingsNavigationActive}
              icon="settings-alt"
              label="Settings"
              onSelect={() => setSecondaryNav(isSettingsNavigationActive ? null : SETTINGS_NAV_KEY)}
            >
              <SettingsNavigation />
            </NavGroup>
          </Box>

          <Box as="li" mt="auto">
            <Link external href={PANTHER_DOCS_LINK}>
              <Flex
                align="center"
                fontSize="medium"
                fontWeight="normal"
                borderRadius="small"
                px={4}
                py={3}
                color="gray-50"
                _hover={{
                  color: 'gray-50',
                  backgroundColor: 'navyblue-500',
                }}
              >
                <Icon type="docs" size="medium" mr={3} />
                <Box>Documentation</Box>
              </Flex>
            </Link>
          </Box>

          <Box as="li">
            <NavLink icon="help" label="Support" to={urls.account.support()} />
          </Box>
        </Flex>

        <Box p={4} backgroundColor="navyblue-800" mt={4}>
          <ProfileInfo />
        </Box>
      </Flex>
    </Flex>
  );
};

export default React.memo(Navigation);
