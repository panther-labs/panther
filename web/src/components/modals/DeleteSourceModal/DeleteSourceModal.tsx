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
import { ListInfraSourcesDocument } from 'Pages/ListComplianceSources';
import { ListLogSourcesDocument } from 'Pages/ListLogSources';
import { INTEGRATION_TYPES } from 'Source/constants';
import BaseConfirmModal from 'Components/modals/BaseConfirmModal';
import { useDeleteSource } from './graphql/deleteSource.generated';

export interface DeleteSourceModalProps {
  source: Integration;
}

const DeleteSourceModal: React.FC<DeleteSourceModalProps> = ({ source }) => {
  const isInfraSource = source.integrationType === INTEGRATION_TYPES.AWS_INFRA;
  const sourceDisplayName = source.integrationLabel || source.integrationId;
  const mutation = useDeleteSource({
    variables: {
      id: source.integrationId,
    },
    refetchQueries: [{ query: isInfraSource ? ListInfraSourcesDocument : ListLogSourcesDocument }],
  });

  return (
    <BaseConfirmModal
      mutation={mutation}
      title={`Delete ${sourceDisplayName}`}
      subtitle={`Are you sure you want to delete ${sourceDisplayName}?`}
      onSuccessMsg={`Successfully deleted ${sourceDisplayName}`}
      onErrorMsg={`Failed to delete ${sourceDisplayName}`}
    />
  );
};

export default DeleteSourceModal;
