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
import { Integration } from 'Generated/schema';
import { LIST_INFRA_SOURCES } from 'Pages/list-compliance-sources/subcomponents/compliance-source-table';
import { LIST_LOG_SOURCES } from 'Pages/list-log-sources/subcomponents/log-source-table';
import { useMutation, gql } from '@apollo/client';
import BaseDeleteModal from 'Components/modals/base-delete-modal';
import { INTEGRATION_TYPES } from 'Source/constants';

const DELETE_SOURCE = gql`
  mutation DeleteSource($id: ID!) {
    deleteIntegration(id: $id)
  }
`;

export interface DeleteSourceModalProps {
  source: Integration;
}

const DeleteSourceModal: React.FC<DeleteSourceModalProps> = ({ source }) => {
  const isInfraSource = source.integrationType === INTEGRATION_TYPES.AWS_INFRA;
  const sourceDisplayName = source.integrationLabel || source.integrationId;
  const mutation = useMutation<boolean, { id: string }>(DELETE_SOURCE, {
    variables: {
      id: source.integrationId,
    },
    refetchQueries: [{ query: isInfraSource ? LIST_INFRA_SOURCES : LIST_LOG_SOURCES }],
  });

  return <BaseDeleteModal mutation={mutation} itemDisplayName={sourceDisplayName} />;
};

export default DeleteSourceModal;
