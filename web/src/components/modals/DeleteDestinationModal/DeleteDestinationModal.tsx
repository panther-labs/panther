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
import { Destination } from 'Generated/schema';
import { useDeleteOutput } from './graphql/deleteOutput.generated';
import OptimisticConfirmModal from '../OptimisticConfirmModal';

export interface DeleteDestinationModalProps extends ModalProps {
  destination: Destination;
}

const DeleteDestinationModal: React.FC<DeleteDestinationModalProps> = ({
  destination,
  ...rest
}) => {
  const destinationDisplayName = destination.displayName || destination.outputId;
  const { pushSnackbar } = useSnackbar();
  const [deleteDestination] = useDeleteOutput({
    variables: {
      id: destination.outputId,
    },
    optimisticResponse: {
      deleteDestination: true,
    },
    update: async cache => {
      cache.modify('ROOT_QUERY', {
        destinations: (destinations, helpers) => {
          const destinationRef = helpers.toReference(destination);
          return destinations.filter(dest => dest.__ref !== destinationRef.__ref);
        },
      });
      cache.gc();
    },
    onCompleted: () => {
      pushSnackbar({
        variant: 'success',
        title: `Successfully deleted destination: ${destinationDisplayName}`,
      });
    },
    onError: () => {
      pushSnackbar({
        variant: 'error',
        title: `Failed to delete destination: ${destinationDisplayName}`,
      });
    },
  });

  return (
    <OptimisticConfirmModal
      title={`Delete ${destinationDisplayName}`}
      subtitle={`Are you sure you want to delete ${destinationDisplayName}?`}
      onConfirm={deleteDestination}
      {...rest}
    />
  );
};

export default DeleteDestinationModal;
