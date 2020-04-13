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

/* eslint-disable react/display-name */

import React from 'react';
import { Text, TableProps, Tooltip, Label } from 'pouncejs';
import { ComplianceItem, ComplianceStatusEnum } from 'Generated/schema';
import { capitalize, formatDatetime } from 'Helpers/utils';
import SuppressButton from 'Components/buttons/SuppressButton';
import RemediationButton from 'Components/buttons/RemediationButton';

// The columns that the associated table will show
const columns = [
  // The name is the `id` of the resource
  {
    key: 'resourceId',
    header: 'Resource',
    flex: '0 0 400px',
  },

  {
    key: 'status',
    header: 'Status',
    flex: '0 0 125px',
    renderCell: ({ status, errorMessage }) => {
      const hasErrored = status === ComplianceStatusEnum.Error;
      const textNode = (
        <Text size="medium" color={status === ComplianceStatusEnum.Pass ? 'green300' : 'red300'}>
          {capitalize(status.toLowerCase())}
          {hasErrored && ' *'}
        </Text>
      );

      if (errorMessage) {
        return (
          <Tooltip positioning="down" content={<Label size="medium">{errorMessage}</Label>}>
            {textNode}
          </Tooltip>
        );
      }

      return textNode;
    },
  },
  {
    key: 'integrationLabel',
    flex: '1 0 100px',
    header: 'Source',
  },

  // Render badges to showcase severity
  {
    key: 'lastUpdated',
    flex: '1 0 170px',
    header: 'Last Updated',
    renderCell: ({ lastUpdated }) => <Text size="medium">{formatDatetime(lastUpdated)}</Text>,
  },

  // The remediation button
  {
    key: 'remediationOptions',
    flex: '0 0 140px',
    renderColumnHeader: () => null,
    renderCell: (complianceItem, index) => {
      return (
        complianceItem.status !== ComplianceStatusEnum.Pass && (
          <RemediationButton
            buttonVariant={index % 2 === 0 ? 'default' : 'secondary'}
            policyId={complianceItem.policyId}
            resourceId={complianceItem.resourceId}
          />
        )
      );
    },
  },

  // The suppress button
  {
    key: 'suppressionOptions',
    flex: '0 0 120px',
    renderColumnHeader: () => null,
    renderCell: (complianceItem, index) => {
      return !complianceItem.suppressed ? (
        <SuppressButton
          buttonVariant={index % 2 === 0 ? 'default' : 'secondary'}
          policyIds={[complianceItem.policyId]}
          resourcePatterns={[complianceItem.resourceId]}
        />
      ) : (
        <Label color="orange300" size="medium" mx={2}>
          IGNORED
        </Label>
      );
    },
  },
] as TableProps<ComplianceItem>['columns'];

export default columns;
