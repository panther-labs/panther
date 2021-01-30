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
import { PolicySummary } from 'Source/graphql/fragments/PolicySummary.generated';
import { PolicyDetails } from 'Source/graphql/fragments/PolicyDetails.generated';
import useRouter from 'Hooks/useRouter';
import urls from 'Source/urls';
import { useDeletePolicy } from './graphql/deletePolicy.generated';
import OptimisticConfirmModal from '../OptimisticConfirmModal';

export interface DeletePolicyModalProps extends ModalProps {
  policy: PolicySummary | PolicyDetails;
}

const DeletePolicyModal: React.FC<DeletePolicyModalProps> = ({ policy, ...rest }) => {
  const { location, history } = useRouter<{ id?: string }>();
  const { pushSnackbar } = useSnackbar();
  const policyDisplayName = policy.displayName || policy.id;
  const [confirm] = useDeletePolicy({
    variables: {
      input: {
        policies: [
          {
            id: policy.id,
          },
        ],
      },
    },
    optimisticResponse: {
      deletePolicy: true,
    },
    update: async cache => {
      cache.modify('ROOT_QUERY', {
        policies: (data, helpers) => {
          const policyRef = helpers.toReference({ __typename: 'Policy', id: policy.id });
          return {
            ...data,
            policies: data.policies.filter(p => p.__ref !== policyRef.__ref),
          };
        },
        policy: (data, helpers) => {
          const policyRef = helpers.toReference({ __typename: 'Policy', id: policy.id });
          if (policyRef.__ref !== data.__ref) {
            return data;
          }
          return helpers.DELETE;
        },
      });

      cache.gc();
    },
    onCompleted: () => {
      pushSnackbar({
        variant: 'success',
        title: `Successfully deleted policy: ${policyDisplayName}`,
      });
    },
    onError: () => {
      pushSnackbar({
        variant: 'error',
        title: `Failed to delete policy: ${policyDisplayName}`,
      });
    },
  });

  function onConfirm() {
    if (location.pathname.includes(policy.id)) {
      // if we were on the particular policy's details page or edit page --> redirect on delete
      history.push(urls.compliance.policies.list());
    }
    return confirm();
  }
  return (
    <OptimisticConfirmModal
      title={`Delete ${policyDisplayName}`}
      subtitle={`Are you sure you want to delete ${policyDisplayName}?`}
      onConfirm={onConfirm}
      {...rest}
    />
  );
};

export default DeletePolicyModal;
