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
import { Button, ButtonProps } from 'pouncejs';
import { ResourceDetails, PolicyDetails } from 'Generated/schema';
import usePolicySuppression from 'Hooks/usePolicySuppression';

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
    <Button
      size="small"
      variant={buttonVariant}
      onClick={() => suppressPolicies()}
      disabled={loading}
    >
      Ignore
    </Button>
  );
};

export default React.memo(SuppressButton);
