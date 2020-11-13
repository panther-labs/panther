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
import { FastField, Form, Formik } from 'formik';
import { Box, Flex, Text, useSnackbar } from 'pouncejs';
import { AlertStatusesEnum } from 'Generated/schema';
import FormikCombobox from 'Components/fields/ComboBox';
import { capitalize, extractErrorMessage } from 'Helpers/utils';
import SubmitButton from 'Components/buttons/SubmitButton';
import { useSelect } from 'Components/utils/SelectContext';
import { useUpdateAlertStatus } from 'Source/graphql/queries';
import { EventEnum, SrcEnum, trackEvent } from 'Helpers/analytics';

const initialValues = {
  status: AlertStatusesEnum.Resolved,
};

const statusOptions = Object.values(AlertStatusesEnum);

const filterItemToString = (item: AlertStatusesEnum) =>
  capitalize(item === AlertStatusesEnum.Closed ? 'Invalid' : item.toLowerCase());

interface ListAlertSelectionFormValues {
  status: AlertStatusesEnum;
}

const ListAlertSelection: React.FC = () => {
  const { selection, resetSelection } = useSelect();
  const { pushSnackbar } = useSnackbar();
  const [updateAlertStatus] = useUpdateAlertStatus({
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
    onCompleted: data => {
      const { status, severity } = data.updateAlertStatus[0];
      trackEvent({
        event: EventEnum.BulkUpdatedAlertStatus,
        src: SrcEnum.Alerts,
        data: { status, severity },
      });
      resetSelection();
      pushSnackbar({
        variant: 'success',
        title: `${data.updateAlertStatus.length} Alert(s) set to ${capitalize(
          (status === AlertStatusesEnum.Closed ? 'INVALID' : status).toLowerCase()
        )}`,
      });
    },
    onError: error => {
      pushSnackbar({
        variant: 'error',
        title: `Failed to bulk update alert(s) status`,
        description: extractErrorMessage(error),
      });
    },
  });

  const onSubmit = React.useCallback(
    (values: ListAlertSelectionFormValues) =>
      updateAlertStatus({
        variables: { input: { status: values.status, alertIds: selection } },
      }),
    [selection]
  );

  return (
    <Flex justify="flex-end" align="center">
      <Formik<ListAlertSelectionFormValues> initialValues={initialValues} onSubmit={onSubmit}>
        <Form>
          <Flex spacing={4} align="center">
            <Text>{selection.length} Selected</Text>
            <Box width={150}>
              <FastField
                name="status"
                as={FormikCombobox}
                items={statusOptions}
                itemToString={filterItemToString}
                label="Status"
                placeholder="Select statuses"
              />
            </Box>
            <SubmitButton variantColor="violet" allowPristineSubmission>
              Apply
            </SubmitButton>
          </Flex>
        </Form>
      </Formik>
    </Flex>
  );
};

export default React.memo(ListAlertSelection);
