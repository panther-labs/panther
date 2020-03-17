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
import { RuleSummary, RuleDetails, ListRulesInput } from 'Generated/schema';
import useRouter from 'Hooks/useRouter';
import urls from 'Source/urls';
import { ListRulesDocument } from 'Pages/ListRules';
import BaseConfirmModal from 'Components/modals/BaseConfirmModal';
// Delete Rule and Delete Policy uses the same endpoint
import { convertObjArrayValuesToCsv } from 'Helpers/utils';
import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import { useDeletePolicy } from '../DeletePolicyModal/graphql/deletePolicy.generated';

export interface DeleteRuleModalProps {
  rule: RuleDetails | RuleSummary;
}

const DeleteRuleModal: React.FC<DeleteRuleModalProps> = ({ rule }) => {
  const { location, history } = useRouter<{ id?: string }>();
  const ruleDisplayName = rule.displayName || rule.id;
  const { requestParams } = useRequestParamsWithPagination<ListRulesInput>();
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
      const { rules } = cache.readQuery({
        query: ListRulesDocument,
        variables: {
          input: convertObjArrayValuesToCsv(requestParams),
        },
      });
      const newRules = rules.rules.filter(r => r.id !== rule.id);
      cache.writeQuery({
        query: ListRulesDocument,
        data: { rules: { ...rules, rules: [...newRules] } },
        variables: {
          input: convertObjArrayValuesToCsv(requestParams),
        },
      });
      cache.gc();
    },
  });

  console.log('DELETE RULE MODAL');

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
