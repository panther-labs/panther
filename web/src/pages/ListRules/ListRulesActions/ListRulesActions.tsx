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
import { LOG_TYPES } from 'Source/constants';
import FormikCombobox from 'Components/fields/ComboBox';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import FormikTextInput from 'Components/fields/TextInput';
import { Box, Button, Card, Flex, Icon } from 'pouncejs';
import CreateButton from 'Pages/ListRules/CreateButton';
import ErrorBoundary from 'Components/ErrorBoundary';
import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import isEmpty from 'lodash-es/isEmpty';
import pick from 'lodash-es/pick';

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
      items: LOG_TYPES,
      label: 'Log Types',
      inputProps: {
        placeholder: 'Start typing logs...',
      },
    },
  },
  severity: {
    component: FormikCombobox,
    props: {
      label: 'Severity',
      items: severityOptions,
      itemToString: (severity: SeverityEnum) => capitalize(severity.toLowerCase()),
      inputProps: {
        placeholder: 'Choose a severity...',
      },
    },
  },
  tags: {
    component: FormikMultiCombobox,
    props: {
      label: 'Tags',
      searchable: true,
      allowAdditions: true,
      items: [] as string[],
      inputProps: {
        placeholder: 'Filter with tags...',
      },
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

  return (
    <React.Fragment>
      <Flex justify="flex-end" mb={6}>
        <Box position="relative" mr={5}>
          <Button
            size="large"
            variant="default"
            onClick={() => setFiltersVisibility(!areFiltersVisible)}
          >
            <Flex>
              <Icon type="filter" size="small" mr={3} />
              Filter Options {filtersCount ? `(${filtersCount})` : ''}
            </Flex>
          </Button>
        </Box>
        <CreateButton />
      </Flex>
      {areFiltersVisible && (
        <ErrorBoundary>
          <Card p={6} mb={6}>
            <GenerateFiltersGroup<ListRulesFiltersValues>
              filters={filters}
              onCancel={() => setFiltersVisibility(false)}
              onSubmit={updateRequestParamsAndResetPaging}
              initialValues={initialFilterValues}
            />
          </Card>
        </ErrorBoundary>
      )}
    </React.Fragment>
  );
};

export default React.memo(ListRulesActions);
