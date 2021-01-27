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
import { ModalProps, useSnackbar } from 'pouncejs';
import OptimisticConfirmModal from 'Components/modals/OptimisticConfirmModal';
import { CustomLogTeaser } from 'Source/graphql/fragments/CustomLogTeaser.generated';
import { CustomLogFull } from 'Source/graphql/fragments/CustomLogFull.generated';
import urls from 'Source/urls';
import useRouter from 'Hooks/useRouter';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import { useDeleteCustomLog } from './graphql/deleteCustomLog.generated';

export interface DeleteCustomLogModalProps extends ModalProps {
  customLog: CustomLogTeaser | CustomLogFull;
}

const DeleteCustomLogModal: React.FC<DeleteCustomLogModalProps> = ({ customLog, ...rest }) => {
  const { pushSnackbar } = useSnackbar();
  const { history, location } = useRouter();
  const [deleteCustomLog] = useDeleteCustomLog({
    variables: {
      input: {
        logType: customLog.logType,
        revision: customLog.revision,
      },
    },
    // FIXME: We removed optimistic response from this request until we upgrade apollo-client
    // issue: https://github.com/apollographql/apollo-client/issues/5790
    update: (
      cache,
      {
        data: {
          deleteCustomLog: { error },
        },
      }
    ) => {
      if (error) {
        return;
      }

      cache.modify('ROOT_QUERY', {
        listCustomLogs(customLogs, { toReference }) {
          const deletedCustomLog = toReference({
            __typename: 'CustomLogRecord',
            logType: customLog.logType,
          });
          return customLogs.filter(r => r.__ref !== deletedCustomLog.__ref);
        },
        listAvailableLogTypes: queryData => {
          return {
            ...queryData,
            logTypes: queryData.logTypes.filter(logType => logType !== customLog.logType),
          };
        },
      });
      cache.gc();
    },
    onCompleted: ({ deleteCustomLog: { error } }) => {
      if (error) {
        pushSnackbar({
          variant: 'error',
          title: error.message,
        });
        trackError({ event: TrackErrorEnum.FailedToDeleteCustomLog, src: SrcEnum.CustomLogs });
      } else {
        trackEvent({ event: EventEnum.DeletedCustomLog, src: SrcEnum.CustomLogs });
      }
    },
    onError: () => {
      pushSnackbar({
        variant: 'error',
        title: 'Failed to delete your custom schema',
      });
      trackError({ event: TrackErrorEnum.FailedToDeleteCustomLog, src: SrcEnum.CustomLogs });
    },
  });

  function onConfirm() {
    // if we were on the particular custom schema's details page --> redirect on delete
    if (location.pathname === urls.logAnalysis.customLogs.details(customLog.logType)) {
      history.push(urls.logAnalysis.customLogs.list());
    }

    return deleteCustomLog();
  }

  return (
    <OptimisticConfirmModal
      onConfirm={onConfirm}
      title="Delete Custom Schema"
      subtitle={[`Are you sure you want to delete `, <b key={0}>{customLog.logType}?</b>]}
      {...rest}
    />
  );
};

export default DeleteCustomLogModal;
