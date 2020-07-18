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
import {
  useSnackbar,
  Dropdown,
  DropdownButton,
  AbstractButton,
  DropdownMenu,
  DropdownItem,
  Tooltip,
  Flex,
  Box,
  Icon,
} from 'pouncejs';
import { AlertStatusesEnum } from 'Generated/schema';
import AlertStatusBadge from 'Components/AlertStatusBadge';
import { extractErrorMessage, formatDatetime } from 'Helpers/utils';
import { AlertSummaryFull } from 'Source/graphql/fragments/AlertSummaryFull.generated';
import { useUpdateAlertStatus } from './graphql/updateAlertStatus.generated';

interface UpdateAlertDropdownProps {
  alert: AlertSummaryFull;
}

const UpdateAlertDropdown: React.FC<UpdateAlertDropdownProps> = ({ alert }) => {
  const { status } = alert;
  const { pushSnackbar } = useSnackbar();

  const [updateAlertStatus] = useUpdateAlertStatus({
    variables: {
      input: {
        status,
        alertId: alert.alertId,
      },
    },

    // This hook ensures we also update the AlertDetails item in the cache
    update: (cache, { data }) => {
      cache.modify({
        id: cache.identify({
          __typename: 'AlertDetails',
          alertId: data.updateAlertStatus.alertId,
        }),
        fields: {
          status: () => data.updateAlertStatus.status,
          lastUpdatedBy: () => data.updateAlertStatus.lastUpdatedBy,
          lastUpdatedByTime: () => data.updateAlertStatus.lastUpdatedByTime,
        },
      });
    },
    // We want to simulate an instant change in the UI which will fallback if there's a failure
    optimisticResponse: data => ({
      updateAlertStatus: {
        ...alert,
        status: data.input.status,
      },
    }),
    onCompleted: data => {
      pushSnackbar({
        variant: 'success',
        title: `Set alert to ${data.updateAlertStatus.status.toLowerCase()}`,
      });
    },
    onError: error => {
      pushSnackbar({
        variant: 'error',
        title: `Failed to set the alert status`,
        description: extractErrorMessage(error),
      });
    },
  });

  const availableStatusesEntries = React.useMemo(() => Object.entries(AlertStatusesEnum), []);

  // Extract a name to display
  const getLastUpdatedBy = React.useCallback(() => {
    if (!alert.lastUpdatedBy) {
      return null;
    }
    if (alert.lastUpdatedBy.givenName && alert.lastUpdatedBy.familyName) {
      return `${alert.lastUpdatedBy.givenName} ${alert.lastUpdatedBy.familyName}`;
    }
    if (!alert.lastUpdatedBy.givenName && alert.lastUpdatedBy.familyName) {
      return alert.lastUpdatedBy.familyName;
    }
    if (alert.lastUpdatedBy.givenName && !alert.lastUpdatedBy.familyName) {
      return alert.lastUpdatedBy.givenName;
    }
    return alert.lastUpdatedBy.email;
  }, [alert]);

  const lastUpdatedBy = React.useMemo(() => getLastUpdatedBy(), [alert]);

  // Format the timestamp
  const lastUpdatedByTime = React.useMemo(() => formatDatetime(alert.lastUpdatedByTime), [alert]);

  // Create our dropdown button
  const dropdownButton = React.useMemo(
    () => (
      <DropdownButton as={AbstractButton} outline="none" aria-label="Alert Status Options">
        <AlertStatusBadge status={status} />
      </DropdownButton>
    ),
    [alert]
  );

  // Create a wrapped dropdown button with a tooltip
  const wrappedDropdownButton = React.useMemo(
    () =>
      lastUpdatedBy ? (
        <Tooltip
          content={
            <Flex spacing={1}>
              <Flex direction="column" spacing={1}>
                <Box id="user-name-label">By</Box>
                <Box id="updated-by-timestamp-label">At</Box>
              </Flex>
              <Flex direction="column" spacing={1} fontWeight="bold">
                <Box aria-labelledby="user-name-label">{lastUpdatedBy}</Box>
                <Box aria-labelledby="updated-by-timestamp-label">{lastUpdatedByTime}</Box>
              </Flex>
            </Flex>
          }
        >
          {dropdownButton}
        </Tooltip>
      ) : (
        dropdownButton
      ),
    [alert]
  );

  return (
    <Dropdown>
      {wrappedDropdownButton}
      <DropdownMenu>
        {availableStatusesEntries.map(([statusKey, statusVal], index) => (
          <DropdownItem
            key={index}
            disabled={status === statusVal}
            onSelect={() =>
              updateAlertStatus({
                variables: { input: { status: statusVal, alertId: alert.alertId } },
              })
            }
          >
            <Flex minWidth={85} spacing={2} justify="space-between" align="center">
              <Box aria-labelledby="status-item">{statusKey}</Box>
              {status === statusVal && <Icon size="x-small" type="check" />}
            </Flex>
          </DropdownItem>
        ))}
      </DropdownMenu>
    </Dropdown>
  );
};

export default UpdateAlertDropdown;
