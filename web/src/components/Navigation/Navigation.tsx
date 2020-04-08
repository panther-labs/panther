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

import React from 'react';
import { Box, Flex, IconButton } from 'pouncejs';
import urls from 'Source/urls';
import { Link } from 'react-router-dom';
import PantherIcon from 'Assets/panther-minimal-logo.svg';
import { PANTHER_SCHEMA_DOCS_LINK } from 'Source/constants';
import useRouter from 'Hooks/useRouter';
import NavIconButton from './NavIconButton';
import SettingsNavigation from './SettingsNavigation';
import ComplianceNavigation from './ComplianceNavigation';
import LogAnalysisNavigation from './LogAnalysisNavigation';
import HistoricalSearchNavigation from './HistoricalSearchNavigation';

const COMPLIANCE_NAV_KEY = 'compliance';
const LOG_ANALYSIS_NAV_KEY = 'logAnalysis';
const SETTINGS_NAV_KEY = 'settings';
const HISTORICAL_SEARCH_NAV_KEY = 'historical';
type NavKeys =
  | typeof COMPLIANCE_NAV_KEY
  | typeof LOG_ANALYSIS_NAV_KEY
  | typeof SETTINGS_NAV_KEY
  | typeof HISTORICAL_SEARCH_NAV_KEY;

const Navigation = () => {
  const {
    location: { pathname },
  } = useRouter();

  const isCompliancePage = pathname.includes(urls.compliance.home());
  const isLogAnalysisPage = pathname.includes(urls.logAnalysis.home());
  const isSettingsPage = pathname.includes(urls.settings.home());
  const [secondaryNav, setSecondaryNav] = React.useState<NavKeys>(null);

  React.useEffect(() => {
    if (isCompliancePage) {
      setSecondaryNav(COMPLIANCE_NAV_KEY);
    } else if (isLogAnalysisPage) {
      setSecondaryNav(LOG_ANALYSIS_NAV_KEY);
    } else if (isSettingsPage) {
      setSecondaryNav(SETTINGS_NAV_KEY);
    } else {
      setSecondaryNav(null);
    }
  }, [isSettingsPage, isCompliancePage, isLogAnalysisPage]);

  const isComplianceNavigationActive = secondaryNav === COMPLIANCE_NAV_KEY;
  const isLogAnalysisNavigationActive = secondaryNav === LOG_ANALYSIS_NAV_KEY;
  const isSettingsNavigationActive = secondaryNav === SETTINGS_NAV_KEY;
  const isHistoricalSearchNavigationActive = secondaryNav === HISTORICAL_SEARCH_NAV_KEY;
  const isSecondaryNavigationActive = secondaryNav !== null;
  return (
    <Flex is="nav" boxShadow="dark50" zIndex={1} position="sticky" top={0} height="100vh">
      <Flex flexDirection="column" width={70} height="100%" boxShadow="dark150">
        <Flex justifyContent="center" pt={7} pb={2}>
          <IconButton variant="primary" is={Link} to="/">
            <img
              src={PantherIcon}
              alt="Panther logo"
              width={30}
              height={30}
              style={{ display: 'block' }}
            />
          </IconButton>
        </Flex>
        <Flex
          flexDirection="column"
          justifyContent="center"
          alignItems="center"
          is="ul"
          flex="1 0 auto"
        >
          <Box is="li">
            <NavIconButton
              active={isComplianceNavigationActive}
              icon="cloud-security"
              tooltipLabel="Cloud Security"
              onClick={() =>
                setSecondaryNav(isComplianceNavigationActive ? null : COMPLIANCE_NAV_KEY)
              }
            />
          </Box>
          <Box is="li">
            <NavIconButton
              active={isLogAnalysisNavigationActive}
              icon="log-analysis"
              tooltipLabel="Log Analysis"
              onClick={() =>
                setSecondaryNav(isLogAnalysisNavigationActive ? null : LOG_ANALYSIS_NAV_KEY)
              }
            />
          </Box>
          <Box is="li" mb="auto">
            <NavIconButton
              active={isHistoricalSearchNavigationActive}
              icon="search"
              tooltipLabel="Historical Search"
              onClick={() =>
                setSecondaryNav(
                  isHistoricalSearchNavigationActive ? null : HISTORICAL_SEARCH_NAV_KEY
                )
              }
            />
          </Box>
          <Box is="li" mt="auto">
            <NavIconButton
              active={false}
              icon="docs"
              is="a"
              href={PANTHER_SCHEMA_DOCS_LINK}
              target="_blank"
              rel="noopener noreferrer"
              tooltipLabel="Documentation"
            />
          </Box>
          <Box is="li">
            <NavIconButton
              active={isSettingsNavigationActive}
              icon="settings"
              tooltipLabel="Settings"
              onClick={() => setSecondaryNav(isSettingsNavigationActive ? null : SETTINGS_NAV_KEY)}
            />
          </Box>
        </Flex>
      </Flex>
      {isSecondaryNavigationActive && (
        <Box width={230} height="100%">
          {secondaryNav === COMPLIANCE_NAV_KEY && <ComplianceNavigation />}
          {secondaryNav === LOG_ANALYSIS_NAV_KEY && <LogAnalysisNavigation />}
          {secondaryNav === SETTINGS_NAV_KEY && <SettingsNavigation />}
          {secondaryNav === HISTORICAL_SEARCH_NAV_KEY && <HistoricalSearchNavigation />}
        </Box>
      )}
    </Flex>
  );
};

export default React.memo(Navigation);
