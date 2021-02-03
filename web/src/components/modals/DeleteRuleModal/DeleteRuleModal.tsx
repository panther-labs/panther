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
import { RuleSummary } from 'Source/graphql/fragments/RuleSummary.generated';
import { RuleDetails } from 'Source/graphql/fragments/RuleDetails.generated';
import useRouter from 'Hooks/useRouter';
import urls from 'Source/urls';
import { useDeleteRule } from './graphql/deleteRule.generated';
import OptimisticConfirmModal from '../OptimisticConfirmModal';

export interface DeleteRuleModalProps extends ModalProps {
  rule: RuleSummary | RuleDetails;
}

const DeleteRuleModal: React.FC<DeleteRuleModalProps> = ({ rule, ...rest }) => {
  const { location, history } = useRouter<{ id?: string }>();
  const { pushSnackbar } = useSnackbar();
  const ruleDisplayName = rule.displayName || rule.id;
  const [confirmDeletion] = useDeleteRule({
    variables: {
      input: {
        rules: [
          {
            id: rule.id,
          },
        ],
      },
    },
    optimisticResponse: {
      deleteRule: true,
    },
    update: async cache => {
      cache.modify('ROOT_QUERY', {
        detections: (data, helpers) => {
          const ruleRef = helpers.toReference({ __typename: 'Rule', id: rule.id });
          return { ...data, detections: data.detections.filter(r => r.__ref !== ruleRef.__ref) };
        },
        rule: (data, helpers) => {
          const ruleRef = helpers.toReference({ __typename: 'Rule', id: rule.id });
          if (ruleRef.__ref !== data.__ref) {
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
        title: `Successfully deleted rule: ${ruleDisplayName}`,
      });
    },
    onError: () => {
      pushSnackbar({
        variant: 'error',
        title: `Failed to delete rule: ${ruleDisplayName}`,
      });
    },
  });

  function onConfirm() {
    if (location.pathname.includes(rule.id)) {
      // if we were on the particular rule's details page or edit page --> redirect on delete
      history.push(urls.logAnalysis.rules.list());
    }
    return confirmDeletion();
  }

  return (
    <OptimisticConfirmModal
      title={`Delete ${ruleDisplayName}`}
      subtitle={`Are you sure you want to delete ${ruleDisplayName}?`}
      onConfirm={onConfirm}
      {...rest}
    />
  );
};

export default DeleteRuleModal;
