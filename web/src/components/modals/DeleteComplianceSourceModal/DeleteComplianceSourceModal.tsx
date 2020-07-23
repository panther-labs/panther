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
import { ComplianceIntegration } from 'Generated/schema';
import { useDeleteComplianceSource } from './graphql/deleteComplianceSource.generated';
import OptimisticConfirmModal from '../OptimisticConfirmModal';

export interface DeleteComplianceSourceModalProps extends ModalProps {
  source: ComplianceIntegration;
}

const DeleteSourceModal: React.FC<DeleteComplianceSourceModalProps> = ({ source, ...rest }) => {
  const sourceDisplayName = source.integrationLabel;
  const { pushSnackbar } = useSnackbar();
  const [deleteComplianceSource] = useDeleteComplianceSource({
    variables: {
      id: source.integrationId,
    },
    optimisticResponse: () => ({ deleteComplianceIntegration: true }),
    update: cache => {
      cache.modify('ROOT_QUERY', {
        listComplianceIntegrations: (queryData, { toReference }) => {
          const deletedSource = toReference(source);
          return queryData.filter(({ __ref }) => __ref !== deletedSource.__ref);
        },
      });
      cache.gc();
    },
    onCompleted: () => {
      pushSnackbar({
        variant: 'success',
        title: `Successfully deleted Compliance source: ${sourceDisplayName}`,
      });
    },
    onError: () => {
      pushSnackbar({
        variant: 'error',
        title: `Failed to delete Compliance source:: ${sourceDisplayName}`,
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
        <Text fontSize="medium" color="gray-300" mt={3} key={1}>
          Deleting this source will not delete the associated Cloudformation stack. You will need to
          manually delete the stack <b>{source.stackName}</b> from the account{' '}
          <b>{source.awsAccountId}</b>
        </Text>,
      ]}
      onConfirm={deleteComplianceSource}
      {...rest}
    />
  );
};

export default DeleteSourceModal;
