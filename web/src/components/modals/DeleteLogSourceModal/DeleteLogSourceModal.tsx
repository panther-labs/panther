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
import { Text } from 'pouncejs';
import { LogIntegration } from 'Generated/schema';
import { ListLogSourcesDocument } from 'Pages/ListLogSources';
import BaseConfirmModal from 'Components/modals/BaseConfirmModal';
import { getLogIntegrationStackName } from 'Helpers/utils';
import { useDeleteLogSource } from './graphql/deleteLogSource.generated';

export interface DeleteLogSourceModalProps {
  source: LogIntegration;
}

const DeleteLogSourceModal: React.FC<DeleteLogSourceModalProps> = ({ source }) => {
  const mutation = useDeleteLogSource({
    variables: {
      id: source.integrationId,
    },
    refetchQueries: [{ query: ListLogSourcesDocument }],
  });

  const sourceDisplayName = source.integrationLabel;
  const stackName = getLogIntegrationStackName(source);
  return (
    <BaseConfirmModal
      mutation={mutation}
      title={`Delete ${sourceDisplayName}`}
      subtitle={[
        <Text size="large" key={0}>
          Are you sure you want to delete <b>{sourceDisplayName}</b>?
        </Text>,
        <Text size="medium" color="grey300" mt={6} key={1}>
          Deleting this source will not delete the associated Cloudformation stack. You will need to
          manually delete the stack {stackName} from the <b>AWS Account {source.awsAccountId}</b>
        </Text>,
      ]}
      onSuccessMsg={`Successfully deleted ${sourceDisplayName}`}
      onErrorMsg={`Failed to delete ${sourceDisplayName}`}
    />
  );
};

export default DeleteLogSourceModal;
