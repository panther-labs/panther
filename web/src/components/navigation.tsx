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
import {
  Box,
  Flex,
  Icon,
  IconButton,
  IconButtonProps,
  IconProps,
  Label,
  MenuItem,
  Tooltip,
} from 'pouncejs';
import urls from 'Source/urls';
import { Link } from 'react-router-dom';
import PantherIcon from 'Assets/panther-minimal-logo.svg';
import { PANTHER_SCHEMA_DOCS_LINK, ADMIN_ROLES_ARRAY } from 'Source/constants';
import useRouter from 'Hooks/useRouter';
import { css } from '@emotion/core';
import RoleRestrictedAccess from 'Components/role-restricted-access';

type INavIconButtonProps = Omit<IconButtonProps, 'variant'> & {
  icon: IconProps['type'];
  tooltipLabel: string;
};

const NavIconButton: React.FC<INavIconButtonProps> = ({ icon, active, tooltipLabel, ...rest }) => (
  <Tooltip content={<Label size="medium">{tooltipLabel}</Label>}>
    <Flex>
      <IconButton {...rest} variant="primary" my={4} active={active} aria-label={tooltipLabel}>
        <Icon type={icon} size="small" />
      </IconButton>
    </Flex>
  </Tooltip>
);

type INavLinkProps = Omit<IconButtonProps, 'variant'> & {
  icon: IconProps['type'];
  label: string;
  to: string;
};

const NavLink: React.FC<INavLinkProps> = ({ icon, label, to }) => {
  const { location } = useRouter();

  return (
    <MenuItem
      width={1}
      variant="primary"
      selected={location.pathname === to}
      my={2}
      is={Link}
      to={to}
      css={css`
        text-decoration: none;
      `}
      aria-label={label}
    >
      <Flex alignItems="center" px={4}>
        <Icon type={icon} size="small" mr={6} />
        {label}
      </Flex>
    </MenuItem>
  );
};

const Navigation = () => {
  const {
    location: { pathname },
  } = useRouter();

  const isSettingsPage = pathname.includes(urls.account.settings.overview());
  const [isSettingsNavOpen, setSettingsNavOpen] = React.useState(isSettingsPage);

  React.useEffect(() => {
    setSettingsNavOpen(isSettingsPage);
  }, [isSettingsPage]);

  return (
    <Flex is="nav" boxShadow="dark50" zIndex={1} position="sticky" top={0} minHeight="100vh">
      <Box width={72} height="100%" boxShadow="dark150">
        <Flex justifyContent="center" py={8} m="auto">
          <IconButton variant="primary" is={Link} to="/" mb={10}>
            <img
              src={PantherIcon}
              alt="Panther logo"
              width={30}
              height={30}
              style={{ display: 'block' }}
            />
          </IconButton>
        </Flex>
        <Flex flexDirection="column" justifyContent="center" alignItems="center" is="ul">
          <li>
            <NavIconButton
              active={pathname === urls.overview()}
              icon="dashboard-alt"
              is={Link}
              to={urls.overview()}
              tooltipLabel="Dashboard"
            />
          </li>
          <li>
            <NavIconButton
              active={pathname === urls.policies.list()}
              icon="policy"
              is={Link}
              to={urls.policies.list()}
              tooltipLabel="Policies"
            />
          </li>
          <li>
            <NavIconButton
              active={pathname === urls.resources.list()}
              icon="resource"
              is={Link}
              to={urls.resources.list()}
              tooltipLabel="Resources"
            />
          </li>
          <li>
            <NavIconButton
              active={pathname === urls.rules.list()}
              icon="rule"
              is={Link}
              to={urls.rules.list()}
              tooltipLabel="Rules"
            />
          </li>
          <li>
            <NavIconButton
              active={pathname === urls.alerts.list()}
              icon="alert"
              is={Link}
              to={urls.alerts.list()}
              tooltipLabel="Alerts"
            />
          </li>
          <li>
            <NavIconButton
              active={false}
              icon="docs"
              is="a"
              href={PANTHER_SCHEMA_DOCS_LINK}
              target="_blank"
              rel="noopener noreferrer"
              tooltipLabel="Documentation"
            />
          </li>
          <li>
            <NavIconButton
              active={isSettingsPage}
              icon="settings"
              onClick={() => setSettingsNavOpen(!isSettingsNavOpen)}
              tooltipLabel="Settings"
            />
          </li>
        </Flex>
      </Box>
      {isSettingsNavOpen && (
        <Box width={205} height="100%">
          <Flex flexDirection="column" mt="35vh" is="ul">
            <RoleRestrictedAccess allowedRoles={ADMIN_ROLES_ARRAY}>
              <Flex is="li">
                <NavLink icon="settings-alt" to={urls.account.settings.general()} label="General" />
              </Flex>
            </RoleRestrictedAccess>
            <Flex is="li">
              <NavLink
                icon="infra-source"
                to={urls.account.settings.sources.list()}
                label="Sources"
              />
            </Flex>
            <Flex is="li">
              <NavLink
                icon="output"
                to={urls.account.settings.destinations()}
                label="Destinations"
              />
            </Flex>
          </Flex>
        </Box>
      )}
    </Flex>
  );
};

export default React.memo(Navigation);
