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
import { Dropdown, Icon, IconButton, MenuItem } from 'pouncejs';
import { ComplianceIntegration } from 'Generated/schema';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/Modal';
import useRouter from 'Hooks/useRouter';
import urls from 'Source/urls';

interface ComplianceSourceTableRowOptionsProps {
  source: ComplianceIntegration;
}

const ComplianceSourceTableRowOptions: React.FC<ComplianceSourceTableRowOptionsProps> = ({
  source,
}) => {
  const { showModal } = useModal();
  const { history } = useRouter();

  return (
    <Dropdown
      trigger={
        <IconButton as="div" variant="default" my={-4}>
          <Icon type="more" size="small" />
        </IconButton>
      }
    >
      <Dropdown.Item
        onSelect={() => history.push(urls.compliance.sources.edit(source.integrationId))}
      >
        <MenuItem variant="default">Edit</MenuItem>
      </Dropdown.Item>
      <Dropdown.Item
        onSelect={() =>
          showModal({
            modal: MODALS.DELETE_COMPLIANCE_SOURCE,
            props: { source },
          })
        }
      >
        <MenuItem variant="default">Delete</MenuItem>
      </Dropdown.Item>
    </Dropdown>
  );
};

export default React.memo(ComplianceSourceTableRowOptions);
