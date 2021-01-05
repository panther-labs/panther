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
import { Dropdown, DropdownButton, DropdownItem, DropdownMenu, IconButton } from 'pouncejs';
import usePolicySuppression from 'Hooks/usePolicySuppression';
import useResourceRemediation from 'Hooks/useResourceRemediation';
import { ComplianceStatusEnum } from 'Generated/schema';
import { PolicyDetailsTableItem } from './PolicyDetailsTable';

interface PolicyDetailsTableRowOptionsProps {
  complianceItem: PolicyDetailsTableItem;
}

const PolicyDetailsTableRowOptions: React.FC<PolicyDetailsTableRowOptionsProps> = ({
  complianceItem,
}) => {
  const { suppressPolicies } = usePolicySuppression({
    policyIds: [complianceItem.policyId],
    resourcePatterns: [complianceItem.resourceId],
  });

  const { remediateResource } = useResourceRemediation({
    policyId: complianceItem.policyId,
    resourceId: complianceItem.resourceId,
  });

  return (
    <Dropdown>
      <DropdownButton
        as={IconButton}
        icon="more"
        variant="ghost"
        variantBorderStyle="circle"
        size="medium"
        aria-label="Resource Options"
      />
      <DropdownMenu>
        <DropdownItem disabled={complianceItem.suppressed} onSelect={suppressPolicies}>
          Ignore
        </DropdownItem>
        <DropdownItem
          disabled={complianceItem.status === ComplianceStatusEnum.Pass}
          onSelect={remediateResource}
        >
          Remediate
        </DropdownItem>
      </DropdownMenu>
    </Dropdown>
  );
};

export default PolicyDetailsTableRowOptions;
