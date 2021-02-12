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
import { Alert, Box } from 'pouncejs';
import urls from 'Source/urls';
import RuleForm from 'Components/forms/RuleForm';
import { AddRuleInput } from 'Generated/schema';
import {
  DEFAULT_DEDUP_FUNCTION,
  DEFAULT_RULE_FUNCTION,
  DEFAULT_TITLE_FUNCTION,
  DEFAULT_ALERT_CONTEXT_FUNCTION,
} from 'Source/constants';
import { extractErrorMessage } from 'Helpers/utils';
import useRouter from 'Hooks/useRouter';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import { useCreateRule } from './graphql/createRule.generated';

export const initialValues: Required<AddRuleInput> = {
  body: `${DEFAULT_RULE_FUNCTION}\n\n${DEFAULT_TITLE_FUNCTION}\n\n${DEFAULT_DEDUP_FUNCTION}\n\n${DEFAULT_ALERT_CONTEXT_FUNCTION}`,
  dedupPeriodMinutes: 60,
  threshold: 1,
  description: '',
  displayName: '',
  enabled: true,
  id: '',
  logTypes: [],
  outputIds: [],
  reference: '',
  runbook: '',
  severity: null,
  tags: [],
  tests: [],
};

const CreateRule: React.FC = () => {
  const { history } = useRouter();
  const [createRule, { error }] = useCreateRule({
    onCompleted: data => {
      trackEvent({ event: EventEnum.AddedRule, src: SrcEnum.Detections });
      history.push(urls.logAnalysis.rules.details(data.addRule.id));
    },
    onError: () => trackError({ event: TrackErrorEnum.FailedToAddRule, src: SrcEnum.Detections }),
  });

  const handleSubmit = React.useCallback(
    values => createRule({ variables: { input: values } }),
    []
  );

  return (
    <Box mb={6}>
      <RuleForm initialValues={initialValues} onSubmit={handleSubmit} />
      {error && (
        <Box mt={2} mb={6}>
          <Alert
            variant="error"
            discardable
            title={
              extractErrorMessage(error) ||
              'An unknown error occured as we were trying to create your rule'
            }
          />
        </Box>
      )}
    </Box>
  );
};

export default CreateRule;
