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
  Flex,
  Box,
  Icon,
  PseudoBox,
} from 'pouncejs';
import { AlertStatusesEnum } from 'Generated/schema';
import AlertStatusBadge from 'Components/AlertStatusBadge';
import { extractErrorMessage, formatDatetime } from 'Helpers/utils';
import { AlertSummaryFull } from 'Source/graphql/fragments/AlertSummaryFull.generated';
import { useListUsers } from 'Pages/Users/graphql/listUsers.generated';
import { useUpdateAlertStatus } from './graphql/updateAlertStatus.generated';

interface UpdateAlertDropdownProps {
  alert: AlertSummaryFull;
}

const UpdateAlertDropdown: React.FC<UpdateAlertDropdownProps> = ({ alert }) => {
  const { pushSnackbar } = useSnackbar();

  const { data: listUsersData } = useListUsers({
    onError: error => {
      pushSnackbar({
        variant: 'error',
        title: `Failed to get user attribution for alerts`,
        description: extractErrorMessage(error),
      });
    },
  });

  const [updateAlertStatus] = useUpdateAlertStatus({
    variables: {
      input: {
        status: alert.status,
        alertId: alert.alertId,
      },
    },

    // This hook ensures we also update the AlertDetails item in the cache
    update: (cache, { data }) => {
      const dataId = cache.identify({
        __typename: 'AlertDetails',
        alertId: data.updateAlertStatus.alertId,
      });
      cache.modify(dataId, {
        status: () => data.updateAlertStatus.status,
        lastUpdatedBy: () => data.updateAlertStatus.lastUpdatedBy,
        lastUpdatedByTime: () => data.updateAlertStatus.lastUpdatedByTime,
      });
      // TODO: when apollo client is updated to 3.0.0-rc.12+, use this code
      // cache.modify({
      //   id: cache.identify({
      //     __typename: 'AlertDetails',
      //     alertId: data.updateAlertStatus.alertId,
      //   }),
      //   fields: {
      //     status: () => data.updateAlertStatus.status,
      //     lastUpdatedBy: () => data.updateAlertStatus.lastUpdatedBy,
      //     lastUpdatedByTime: () => data.updateAlertStatus.lastUpdatedByTime,
      //   },
      // });
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

  // Extracts a user from a list of users by its ID
  const getUser = React.useCallback((listUsers, lastUpdatedBy) => {
    return listUsers?.users.filter((usr: { id: string }) => usr.id === lastUpdatedBy).pop();
  }, []);

  // Returns a display name from a list of users and a specified userId
  const getDisplayName = React.useCallback((lastUpdatedBy, listUsers) => {
    if (!lastUpdatedBy) {
      return '';
    }

    const user = getUser(listUsers, lastUpdatedBy);
    if (!user) {
      return '';
    }

    if (user.givenName && user.familyName) {
      return `${user.givenName} ${user.familyName}`;
    }
    if (!user.givenName && user.familyName) {
      return user.familyName;
    }
    if (user.givenName && !user.familyName) {
      return user.givenName;
    }
    return user.email;
  }, []);

  // Create the display name
  const lastUpdatedBy = React.useMemo(() => getDisplayName(alert.lastUpdatedBy, listUsersData), [
    alert,
    listUsersData,
  ]);

  // Create a formatted timestamp
  const lastUpdatedByTime = React.useMemo(() => formatDatetime(alert.lastUpdatedByTime), [alert]);

  // Create our dropdown button
  const dropdownButton = React.useMemo(
    () => (
      <Flex spacing={1} justify="center" align="center">
        <AlertStatusBadge
          status={alert.status}
          lastUpdatedBy={lastUpdatedBy}
          lastUpdatedByTime={lastUpdatedByTime}
        />
        <DropdownButton
          as={AbstractButton}
          display="inline-flex"
          outline="none"
          aria-label="Alert Status Options"
        >
          <PseudoBox
            as={Icon}
            type="caret-down"
            padding="4px"
            transition="all 0.2s ease-in-out"
            border="1px solid"
            borderColor="navyblue-450"
            borderRadius="50%"
            backgroundColor="transparent"
            _hover={{ backgroundColor: 'navyblue-450' }}
          />
        </DropdownButton>
      </Flex>
    ),
    [alert, lastUpdatedBy, lastUpdatedByTime]
  );

  const availableStatusesEntries = React.useMemo(() => Object.entries(AlertStatusesEnum), []);

  return (
    <Dropdown>
      {dropdownButton}
      <DropdownMenu>
        {availableStatusesEntries.map(([statusKey, statusVal], index) => (
          <DropdownItem
            key={index}
            disabled={alert.status === statusVal}
            onSelect={() =>
              updateAlertStatus({
                variables: { input: { status: statusVal, alertId: alert.alertId } },
              })
            }
          >
            <Flex minWidth={85} spacing={2} justify="space-between" align="center">
              <Box aria-labelledby="status-item">{statusKey}</Box>
              {alert.status === statusVal && <Icon size="x-small" type="check" />}
            </Flex>
          </DropdownItem>
        ))}
      </DropdownMenu>
    </Dropdown>
  );
};

export default UpdateAlertDropdown;
