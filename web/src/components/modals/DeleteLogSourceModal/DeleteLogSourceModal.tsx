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
import { ModalProps, Text, useSnackbar } from 'pouncejs';
import { LogIntegration } from 'Generated/schema';
import { useDeleteLogSource } from './graphql/deleteLogSource.generated';
import OptimisticConfirmModal from '../OptimisticConfirmModal';

export interface DeleteLogSourceModalProps extends ModalProps {
  source: LogIntegration;
  description: string;
}

const DeleteLogSourceModal: React.FC<DeleteLogSourceModalProps> = ({
  source,
  description,
  ...rest
}) => {
  const sourceDisplayName = source.integrationLabel;
  const { pushSnackbar } = useSnackbar();
  const [deleteLogSource] = useDeleteLogSource({
    variables: {
      id: source.integrationId,
    },
    optimisticResponse: () => ({ deleteLogIntegration: true }),
    update: cache => {
      cache.modify('ROOT_QUERY', {
        listLogIntegrations: (queryData, { toReference }) => {
          const deletedSource = toReference(source);
          return queryData.filter(({ __ref }) => __ref !== deletedSource.__ref);
        },
      });
    },
    onCompleted: () => {
      pushSnackbar({
        variant: 'success',
        title: `Successfully deleted source: ${sourceDisplayName}`,
      });
    },
    onError: () => {
      pushSnackbar({
        variant: 'error',
        title: `Failed to delete source: ${sourceDisplayName}`,
      });
    },
  });

  return (
    <OptimisticConfirmModal
      title={`Delete ${sourceDisplayName}`}
      subtitle={[
        <Text key={0}>
          Are you sure you want to delete <b>{sourceDisplayName}</b>?
        </Text>,
        <Text fontSize="medium" mt={6} key={1}>
          {description}
        </Text>,
      ]}
      onConfirm={deleteLogSource}
      {...rest}
    />
  );
};

export default DeleteLogSourceModal;
