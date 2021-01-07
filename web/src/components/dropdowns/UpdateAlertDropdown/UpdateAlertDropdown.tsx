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
  DropdownMenu,
  DropdownItem,
  Flex,
  Box,
  Icon,
  IconButton,
} from 'pouncejs';
import { AlertStatusesEnum } from 'Generated/schema';
import AlertStatusBadge from 'Components/badges/AlertStatusBadge';
import { extractErrorMessage, formatDatetime, getUserDisplayName, capitalize } from 'Helpers/utils';
import { AlertSummaryFull } from 'Source/graphql/fragments/AlertSummaryFull.generated';
import { useListUsers } from 'Pages/Users/graphql/listUsers.generated';
import { EventEnum, SrcEnum, trackEvent } from 'Helpers/analytics';
import { useUpdateAlertStatus } from 'Source/graphql/queries';

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
        alertIds: [alert.alertId],
      },
    },

    // This hook ensures we also update the AlertDetails item in the cache
    update: (cache, { data }) => {
      data.updateAlertStatus.forEach(newAlert => {
        const dataId = cache.identify({
          __typename: 'AlertDetails',
          alertId: newAlert.alertId,
        });
        cache.modify(dataId, {
          status: () => newAlert.status,
          lastUpdatedBy: () => newAlert.lastUpdatedBy,
          lastUpdatedByTime: () => newAlert.lastUpdatedByTime,
        });
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
      updateAlertStatus: [
        {
          ...alert,
          status: data.input.status,
        },
      ],
    }),
    onCompleted: data => {
      const { status, severity } = data.updateAlertStatus[0];
      trackEvent({
        event: EventEnum.UpdatedAlertStatus,
        src: SrcEnum.Alerts,
        data: { status, severity },
      });
      pushSnackbar({
        variant: 'success',
        title: `Alert set to ${capitalize(
          (status === AlertStatusesEnum.Closed ? 'INVALID' : status).toLowerCase()
        )}`,
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

  const user = listUsersData?.users.find(({ id }) => id === alert.lastUpdatedBy);
  const lastUpdatedBy = getUserDisplayName(user);
  const lastUpdatedByTime = formatDatetime(alert.lastUpdatedByTime);
  const availableStatusesEntries = React.useMemo(() => Object.entries(AlertStatusesEnum), []);

  return (
    <Flex spacing={1} justify="center" align="center">
      <AlertStatusBadge
        status={alert.status}
        lastUpdatedBy={lastUpdatedBy}
        lastUpdatedByTime={lastUpdatedByTime}
      />
      <Dropdown>
        <DropdownButton as={Box} display="inline-flex">
          <IconButton
            variant="outline"
            variantColor="navyblue"
            variantBorderStyle="circle"
            icon="caret-down"
            size="small"
            aria-label="Change Alert Status"
          />
        </DropdownButton>
        <DropdownMenu>
          {availableStatusesEntries.map(([statusKey, statusVal], index) => (
            <DropdownItem
              key={index}
              disabled={alert.status === statusVal}
              onSelect={() =>
                updateAlertStatus({
                  variables: { input: { status: statusVal, alertIds: [alert.alertId] } },
                })
              }
            >
              <Flex minWidth={85} spacing={2} justify="space-between" align="center">
                <Box>{statusKey === 'Closed' ? 'Invalid' : statusKey}</Box>
                {alert.status === statusVal && <Icon size="x-small" type="check" />}
              </Flex>
            </DropdownItem>
          ))}
        </DropdownMenu>
      </Dropdown>
    </Flex>
  );
};

export default UpdateAlertDropdown;
