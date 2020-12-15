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
import { Box, Flex, Img, Link, Divider } from 'pouncejs';
import urls from 'Source/urls';
import { Link as RRLink } from 'react-router-dom';
import PantherIcon from 'Assets/panther-minimal-logo.svg';
import { animated, useTransition } from 'react-spring';
import { PANTHER_DOCS_LINK } from 'Source/constants';
import useRouter from 'Hooks/useRouter';
import NavIconButton from './NavIconButton';
import ProfileIcon from './ProfileIcon';
import {
  SettingsNavigation,
  ComplianceNavigation,
  LogAnalysisNavigation,
} from './SecondaryNavigations';

const SECONDARY_NAV_WIDTH = 200;
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
    const isLogAnalysisPage = pathname.includes(urls.logAnalysis.home());
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
  const isSecondaryNavigationActive = secondaryNav !== null;

  const transitions = useTransition(isSecondaryNavigationActive, null, {
    initial: { width: SECONDARY_NAV_WIDTH, opacity: 0 },
    from: { width: 0, opacity: 0 },
    enter: { width: SECONDARY_NAV_WIDTH, opacity: 1 },
    leave: { width: 0, opacity: 0 },
  });

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
      <Flex as="nav" direction="column" width={60} height="100%" aria-label="Main" align="center">
        <Box as={RRLink} to="/" py={3} mb={3}>
          <Img
            src={PantherIcon}
            alt="Panther logo"
            nativeWidth={30}
            nativeHeight={30}
            display="block"
          />
        </Box>
        <ProfileIcon />
        <Divider mt={6} mb={4} width={37} color="navyblue-300" />
        <Flex direction="column" as="ul" flex="1 0 auto" spacing={4}>
          <Box as="li">
            <NavIconButton
              active={isLogAnalysisNavigationActive}
              icon="log-analysis"
              tooltipLabel="Log Analysis"
              onClick={() =>
                setSecondaryNav(isLogAnalysisNavigationActive ? null : LOG_ANALYSIS_NAV_KEY)
              }
            />
          </Box>
          <Box as="li">
            <NavIconButton
              active={isComplianceNavigationActive}
              icon="cloud-security"
              tooltipLabel="Cloud Security"
              onClick={() =>
                setSecondaryNav(isComplianceNavigationActive ? null : COMPLIANCE_NAV_KEY)
              }
            />
          </Box>
          <Box as="li" mb="auto">
            <NavIconButton
              active={isSettingsNavigationActive}
              icon="settings"
              tooltipLabel="Settings"
              onClick={() => setSecondaryNav(isSettingsNavigationActive ? null : SETTINGS_NAV_KEY)}
            />
          </Box>
          <Box as="li" mt="auto">
            <Link external href={PANTHER_DOCS_LINK} tabIndex={-1}>
              <NavIconButton active={false} icon="docs" tooltipLabel="Documentation" />
            </Link>
          </Box>
          <Box as="li">
            <Link as={RRLink} to={urls.account.support()} tabIndex={-1}>
              <NavIconButton active={false} icon="help" tooltipLabel="Support" />
            </Link>
          </Box>
        </Flex>
      </Flex>
      {transitions.map(
        ({ item, key, props: styles }) =>
          item && (
            <animated.div key={key} style={{ width: 0, ...styles }}>
              <Box height="100%" borderLeft="1px solid" borderColor="navyblue-400" px="14px">
                {secondaryNav === COMPLIANCE_NAV_KEY && <ComplianceNavigation />}
                {secondaryNav === LOG_ANALYSIS_NAV_KEY && <LogAnalysisNavigation />}
                {secondaryNav === SETTINGS_NAV_KEY && <SettingsNavigation />}
              </Box>
            </animated.div>
          )
      )}
    </Flex>
  );
};

export default React.memo(Navigation);
