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
import { LIST_POLICIES } from 'Pages/ListPolicies';
import { DeletePolicyInput, PolicySummary, PolicyDetails } from 'Generated/schema';

import { useMutation, gql } from '@apollo/client';
import useRouter from 'Hooks/useRouter';
import urls from 'Source/urls';
import { getOperationName } from '@apollo/client/utilities/graphql/getFromAST';
import BaseConfirmModal from 'Components/Modals/base-confirm-modal';

const DELETE_POLICY = gql`
  mutation DeletePolicy($input: DeletePolicyInput!) {
    deletePolicy(input: $input)
  }
`;

export interface DeletePolicyModalProps {
  policy: PolicyDetails | PolicySummary;
}

const DeletePolicyModal: React.FC<DeletePolicyModalProps> = ({ policy }) => {
  const { location, history } = useRouter<{ id?: string }>();
  const policyDisplayName = policy.displayName || policy.id;
  const mutation = useMutation<boolean, { input: DeletePolicyInput }>(DELETE_POLICY, {
    awaitRefetchQueries: true,
    refetchQueries: [getOperationName(LIST_POLICIES)],
    variables: {
      input: {
        policies: [
          {
            id: policy.id,
          },
        ],
      },
    },
  });

  return (
    <BaseConfirmModal
      mutation={mutation}
      title={`Delete ${policyDisplayName}`}
      subtitle={`Are you sure you want to delete ${policyDisplayName}?`}
      onSuccessMsg={`Successfully deleted ${policyDisplayName}`}
      onErrorMsg={`Failed to delete ${policyDisplayName}`}
      onSuccess={() => {
        if (location.pathname.includes(policy.id)) {
          // if we were on the particular policy's details page or edit page --> redirect on delete
          history.push(urls.compliance.policies.list());
        }
      }}
    />
  );
};

export default DeletePolicyModal;
