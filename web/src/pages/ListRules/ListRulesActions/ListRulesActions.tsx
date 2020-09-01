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
import { SeverityEnum, ListRulesInput } from 'Generated/schema';
import GenerateFiltersGroup from 'Components/utils/GenerateFiltersGroup';
import { capitalize } from 'Helpers/utils';
import FormikCombobox from 'Components/fields/ComboBox';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import FormikTextInput from 'Components/fields/TextInput';
import { Box, Button, Card, Collapse, Flex, useSnackbar } from 'pouncejs';
import CreateButton from 'Pages/ListRules/CreateButton';
import ErrorBoundary from 'Components/ErrorBoundary';
import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import isEmpty from 'lodash/isEmpty';
import pick from 'lodash/pick';
import Breadcrumbs from 'Components/Breadcrumbs';
import { useListAvailableLogTypes } from 'Source/graphql/queries/listAvailableLogTypes.generated';

const severityOptions = Object.values(SeverityEnum);

export const filters = {
  nameContains: {
    component: FormikTextInput,
    props: {
      label: 'Name contains',
      placeholder: 'Enter a rule name...',
    },
  },
  logTypes: {
    component: FormikMultiCombobox,
    props: {
      searchable: true,
      items: [],
      label: 'Log Types',
      placeholder: 'Start typing logs...',
    },
  },
  severity: {
    component: FormikCombobox,
    props: {
      label: 'Severity',
      items: ['', ...severityOptions],
      itemToString: (severity: SeverityEnum | '') =>
        severity === '' ? 'All' : capitalize(severity.toLowerCase()),
      placeholder: 'Choose a severity...',
    },
  },
  tags: {
    component: FormikMultiCombobox,
    props: {
      label: 'Tags',
      searchable: true,
      allowAdditions: true,
      items: [] as string[],
      placeholder: 'Filter with tags...',
    },
  },
  enabled: {
    component: FormikCombobox,
    props: {
      label: 'Enabled',
      items: ['', 'true', 'false'],
      itemToString: (item: boolean | string) => {
        if (!item) {
          return 'All';
        }
        return item === 'true' ? 'Yes' : 'No';
      },
      placeholder: 'Show only enabled?',
    },
  },
};

export type ListRulesFiltersValues = Pick<
  ListRulesInput,
  'tags' | 'severity' | 'logTypes' | 'nameContains'
>;

const ListRulesActions: React.FC = () => {
  const [areFiltersVisible, setFiltersVisibility] = React.useState(false);
  const { requestParams, updateRequestParamsAndResetPaging } = useRequestParamsWithPagination<
    ListRulesInput
  >();
  const { pushSnackbar } = useSnackbar();
  const { data } = useListAvailableLogTypes({
    onError: () => pushSnackbar({ title: "Couldn't fetch your available log types" }),
  });

  const filterKeys = Object.keys(filters) as (keyof ListRulesInput)[];
  const filtersCount = filterKeys.filter(key => !isEmpty(requestParams[key])).length;

  // If there is at least one filter set visibility to true
  React.useEffect(() => {
    if (filtersCount > 0) {
      setFiltersVisibility(true);
    }
  }, [filtersCount]);

  // The initial filter values for when the filters component first renders. If you see down below,
  // we mount and unmount it depending on whether it's visible or not
  const initialFilterValues = React.useMemo(
    () => pick(requestParams, filterKeys) as ListRulesFiltersValues,
    [requestParams]
  );

  // FIXME: I know this sucks, but we plan to refactor all this logic in the upcoming release
  filters.logTypes.props.items = data?.listAvailableLogTypes.logTypes ?? [];

  return (
    <React.Fragment>
      <Breadcrumbs.Actions>
        <Flex justify="flex-end">
          <Flex spacing={5} justify="flex-end">
            <Button
              variant="outline"
              variantColor="navyblue"
              icon="filter"
              onClick={() => setFiltersVisibility(!areFiltersVisible)}
            >
              Filter Options {filtersCount ? `(${filtersCount})` : ''}
            </Button>
            <CreateButton />
          </Flex>
        </Flex>
      </Breadcrumbs.Actions>
      <Collapse open={areFiltersVisible}>
        <Box pb={6} as="section">
          <Card p={8}>
            <ErrorBoundary>
              <GenerateFiltersGroup<ListRulesFiltersValues>
                filters={filters}
                onSubmit={updateRequestParamsAndResetPaging}
                initialValues={initialFilterValues}
              />
            </ErrorBoundary>
          </Card>
        </Box>
      </Collapse>
    </React.Fragment>
  );
};

export default React.memo(ListRulesActions);
