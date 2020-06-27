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
        size="small"
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
