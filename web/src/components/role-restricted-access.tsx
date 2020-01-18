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
import { RoleNameEnum } from 'Generated/schema';
import useAuth from 'Hooks/useAuth';

export interface RoleRestrictedAccessProps {
  allowedRoles?: RoleNameEnum[];
  deniedRoles?: RoleNameEnum[];
  fallback?: React.ReactElement | null;
  children: React.ReactNode; // we need to specify it due to React.memo(..) down below
}

const RoleRestrictedAccess: React.FC<RoleRestrictedAccessProps> = ({
  allowedRoles,
  deniedRoles,
  fallback = null,
  children,
}) => {
  const { userInfo } = useAuth();

  if (!allowedRoles && !deniedRoles) {
    throw new Error(
      'You should specify either some roles to access the content or some to deny access to'
    );
  }

  if (!userInfo) {
    return fallback;
  }

  if (allowedRoles && userInfo.roles.some(role => allowedRoles.includes(role))) {
    return children as React.ReactElement;
  }

  if (deniedRoles && !userInfo.roles.every(role => deniedRoles.includes(role))) {
    return children as React.ReactElement;
  }

  return fallback;
};

export default React.memo(RoleRestrictedAccess);
