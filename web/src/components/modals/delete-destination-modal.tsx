/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
import { Destination } from 'Generated/schema';
import { useMutation, gql } from '@apollo/client';
import { LIST_DESTINATIONS } from 'Pages/Destinations';
import BaseConfirmModal from 'Components/modals/base-confirm-modal';

const DELETE_DESTINATION = gql`
  mutation DeleteOutput($id: ID!) {
    deleteDestination(id: $id)
  }
`;

export interface DeleteDestinationModalProps {
  destination: Destination;
}

export interface ApolloMutationInput {
  id: string;
}

const DeleteDestinationModal: React.FC<DeleteDestinationModalProps> = ({ destination }) => {
  const destinationDisplayName = destination.displayName || destination.outputId;
  const mutation = useMutation<boolean, ApolloMutationInput>(DELETE_DESTINATION, {
    variables: {
      id: destination.outputId,
    },
    refetchQueries: [{ query: LIST_DESTINATIONS }],
  });

  return (
    <BaseConfirmModal
      mutation={mutation}
      title={`Delete ${destinationDisplayName}`}
      subtitle={`Are you sure you want to delete ${destinationDisplayName}?`}
      onSuccessMsg={`Successfully deleted ${destinationDisplayName}`}
      onErrorMsg={`Failed to delete ${destinationDisplayName}`}
    />
  );
};

export default DeleteDestinationModal;
