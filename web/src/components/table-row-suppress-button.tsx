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
import { Button, ButtonProps } from 'pouncejs';
import { ResourceDetails, PolicyDetails } from 'Generated/schema';
import usePolicySuppression from 'Hooks/usePolicySuppression';
import { READONLY_ROLES_ARRAY } from 'Source/constants';
import RoleRestrictedAccess from 'Components/role-restricted-access';

interface SuppressButtonProps {
  buttonVariant: ButtonProps['variant'];
  resourcePatterns: ResourceDetails['id'][];
  policyIds: PolicyDetails['id'][];
}

const SuppressButton: React.FC<SuppressButtonProps> = ({
  buttonVariant,
  policyIds,
  resourcePatterns,
}) => {
  const { suppressPolicies, loading } = usePolicySuppression({ policyIds, resourcePatterns });

  return (
    <RoleRestrictedAccess deniedRoles={READONLY_ROLES_ARRAY}>
      <Button
        size="small"
        variant={buttonVariant}
        onClick={e => {
          // Table row is clickable, we don't want to navigate away
          e.stopPropagation();
          suppressPolicies();
        }}
        disabled={loading}
      >
        Ignore
      </Button>
    </RoleRestrictedAccess>
  );
};

export default React.memo(SuppressButton);
