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
import { useSnackbar } from 'pouncejs';
import useModal from 'Hooks/useModal';
import { PolicySummary, PolicyDetails } from 'Generated/schema';
import useRouter from 'Hooks/useRouter';
import urls from 'Source/urls';
import BaseConfirmModal from 'Components/modals/BaseConfirmModal';
import { useDeletePolicy } from './graphql/deletePolicy.generated';

export interface DeletePolicyModalProps {
  policy: PolicyDetails | PolicySummary;
}

const DeletePolicyModal: React.FC<DeletePolicyModalProps> = ({ policy }) => {
  const { location, history } = useRouter<{ id?: string }>();
  const policyDisplayName = policy.displayName || policy.id;
  const [confirm, { loading, data, error }] = useDeletePolicy({
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
        policies: (resp, helpers) => {
          const policyRef = helpers.toReference({
            __typename: 'PolicySummary',
            id: policy.id,
          });
          return {
            ...resp,
            policies: resp.policies.filter(p => p.__ref !== policyRef.__ref),
          };
        },
        policy: (resp, helpers) => {
          const policyRef = helpers.toReference({
            __typename: 'PolicyDetails',
            id: policy.id,
          });
          if (policyRef.__ref !== resp.__ref) {
            return resp;
          }
          return helpers.DELETE;
        },
      });

      cache.gc();
    },
  });

  const { pushSnackbar } = useSnackbar();
  const { closeModal } = useModal();

  React.useEffect(() => {
    if (error) {
      pushSnackbar({ variant: 'error', title: `Failed to delete ${policyDisplayName}` });
      closeModal();
    }
    // closeModal();
  }, [error]);

  React.useEffect(() => {
    if (data) {
      pushSnackbar({ variant: 'success', title: `Successfully deleted ${policyDisplayName}` });
      if (location.pathname.includes(policy.id)) {
        // if we were on the particular policy's details page or edit page --> redirect on delete
        history.push(urls.compliance.policies.list());
      }
      closeModal();
    }
  }, [data]);

  return (
    <BaseConfirmModal
      title={`Delete ${policyDisplayName}`}
      subtitle={`Are you sure you want to delete ${policyDisplayName}?`}
      loading={loading}
      onConfirm={confirm}
    />
  );
};

export default DeletePolicyModal;
