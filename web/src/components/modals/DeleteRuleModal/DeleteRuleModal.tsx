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
import { RuleSummary, RuleDetails } from 'Generated/schema';
import useRouter from 'Hooks/useRouter';
import urls from 'Source/urls';
import BaseConfirmModal from 'Components/modals/BaseConfirmModal';
// Delete Rule and Delete Policy uses the same endpoint
import { useDeletePolicy } from '../DeletePolicyModal/graphql/deletePolicy.generated';

export interface DeleteRuleModalProps {
  rule: RuleDetails | RuleSummary;
}

const DeleteRuleModal: React.FC<DeleteRuleModalProps> = ({ rule }) => {
  const { location, history } = useRouter<{ id?: string }>();
  const ruleDisplayName = rule.displayName || rule.id;
  const mutation = useDeletePolicy({
    variables: {
      input: {
        policies: [
          {
            id: rule.id,
          },
        ],
      },
    },
    optimisticResponse: {
      deletePolicy: true,
    },
    update: async cache => {
      cache.modify('ROOT_QUERY', {
        rules: (data, helpers) => {
          const ruleRef = helpers.toReference({
            __typename: 'RuleSummary',
            id: rule.id,
          });
          return { ...data, rules: data.rules.filter(r => r.__ref !== ruleRef.__ref) };
        },
        rule: (data, helpers) => {
          const ruleRef = helpers.toReference({
            __typename: 'RuleDetails',
            id: rule.id,
          });
          if (ruleRef.__ref !== data.__ref) {
            return data;
          }
          return helpers.DELETE;
        },
      });
      cache.gc();
    },
  });

  return (
    <BaseConfirmModal
      mutation={mutation}
      title={`Delete ${ruleDisplayName}`}
      subtitle={`Are you sure you want to delete ${ruleDisplayName}?`}
      onSuccessMsg={`Successfully deleted ${ruleDisplayName}`}
      onErrorMsg={`Failed to delete ${ruleDisplayName}`}
      onSuccess={() => {
        if (location.pathname.includes(rule.id)) {
          // if we were on the particular rule's details page or edit page --> redirect on delete
          history.push(urls.logAnalysis.rules.list());
        }
      }}
    />
  );
};

export default DeleteRuleModal;
