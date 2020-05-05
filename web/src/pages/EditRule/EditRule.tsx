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
import Panel from 'Components/Panel';
import { Alert, Button, Card, Box, useSnackbar } from 'pouncejs';
import RuleForm, { ruleEditableFields } from 'Components/forms/RuleForm';
import { RuleDetails } from 'Generated/schema';
import useModal from 'Hooks/useModal';
import useRouter from 'Hooks/useRouter';
import TablePlaceholder from 'Components/TablePlaceholder';
import { MODALS } from 'Components/utils/Modal';
import { extractErrorMessage, formatJSON } from 'Helpers/utils';
import pick from 'lodash-es/pick';
import { initialValues as createRuleInitialValues } from 'Pages/CreateRule';
import { useRuleDetails } from './graphql/ruleDetails.generated';
import { useUpdateRule } from './graphql/updateRule.generated';

const EditRulePage: React.FC = () => {
  const { match } = useRouter<{ id: string }>();
  const { showModal } = useModal();
  const { pushSnackbar } = useSnackbar();

  const { error: fetchRuleError, data: queryData, loading: isFetchingRule } = useRuleDetails({
    variables: {
      input: {
        ruleId: match.params.id,
      },
    },
  });

  const [updateRule, { error: updateError }] = useUpdateRule({
    onCompleted: () =>
      pushSnackbar({
        variant: 'success',
        title: 'Successfully updated rule!',
      }),
  });

  const handleSubmit = React.useCallback(
    values => updateRule({ variables: { input: values } }),
    []
  );

  const initialValues = React.useMemo(() => {
    if (queryData) {
      const { tests, ...otherInitialValues } = pick(
        queryData.rule,
        ruleEditableFields
      ) as RuleDetails;
      // format any JSON returned from the server simply because we are going to display it
      // within an online web editor. To do that we parse the JSON and re-stringify it using proper
      // spacings that make it pretty (The server of course doesn't store these spacings when
      // it stores JSON, that's why we are making those here in the front-end)
      return {
        ...otherInitialValues,
        tests: tests.map(({ resource, ...restTestData }) => ({
          ...restTestData,
          resource: formatJSON(JSON.parse(resource)),
        })),
      };
    }

    return createRuleInitialValues;
  }, [queryData]);

  if (isFetchingRule) {
    return (
      <Card p={9}>
        <TablePlaceholder rowCount={5} rowHeight={15} />
        <TablePlaceholder rowCount={1} rowHeight={100} />
      </Card>
    );
  }

  if (fetchRuleError) {
    return (
      <Alert
        mb={6}
        variant="error"
        title="Couldn't load the rule details"
        description={
          extractErrorMessage(fetchRuleError) ||
          'There was an error when performing your request, please contact support@runpanther.io'
        }
      />
    );
  }

  return (
    <Box mb={10}>
      <Panel
        size="large"
        title="Rule Settings"
        actions={
          <Button
            variant="default"
            size="large"
            color="red300"
            onClick={() =>
              showModal({
                modal: MODALS.DELETE_RULE,
                props: { rule: queryData.rule },
              })
            }
          >
            Delete
          </Button>
        }
      >
        <RuleForm initialValues={initialValues} onSubmit={handleSubmit} />
      </Panel>
      {updateError && (
        <Alert
          mt={2}
          mb={6}
          variant="error"
          title={
            extractErrorMessage(updateError) ||
            'An unknown error occured as were trying to update your rule'
          }
        />
      )}
    </Box>
  );
};

export default EditRulePage;
