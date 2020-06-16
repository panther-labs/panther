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
import { SeverityEnum, ListAlertsInput } from 'Generated/schema';
import GenerateFiltersGroup from 'Components/utils/GenerateFiltersGroup';
import { capitalize, sanitizeDates, desanitizeDates } from 'Helpers/utils';
import FormikTextInput from 'Components/fields/TextInput';
import FormikCombobox from 'Components/fields/ComboBox';
import useRequestParamsWithInfiniteScroll from 'Hooks/useRequestParamsWithInfiniteScroll';
import { Box, Button, Card, Flex, Icon } from 'pouncejs';
import CreateButton from 'Pages/ListPolicies/CreateButton';
import ErrorBoundary from 'Components/ErrorBoundary';
import isEmpty from 'lodash-es/isEmpty';
import pick from 'lodash-es/pick';

const severityOptions = Object.values(SeverityEnum);

export const filters = {
  contains: {
    component: FormikTextInput,
    props: {
      label: 'Title contains',
      placeholder: 'Enter an alert title...',
    },
  },
  severity: {
    component: FormikCombobox,
    props: {
      label: 'Severity',
      items: ['', ...severityOptions],
      itemToString: (severity: SeverityEnum | '') =>
        severity === '' ? 'All' : capitalize(severity.toLowerCase()),
      inputProps: {
        placeholder: 'Choose a severity...',
      },
    },
  },
  ruleId: {
    component: FormikTextInput,
    props: {
      label: 'Rule ID',
      placeholder: 'Enter a rule ID...',
    },
  },
  eventCountMin: {
    component: FormikTextInput,
    props: {
      label: 'Event count (min)',
      placeholder: 'Enter number...',
      type: 'number',
      min: 0,
    },
  },
  eventCountMax: {
    component: FormikTextInput,
    props: {
      label: 'Event count (max)',
      placeholder: 'Enter number...',
      type: 'number',
      min: 0,
    },
  },
  createdAtAfter: {
    component: FormikTextInput,
    props: {
      label: 'Created After',
      type: 'datetime-local',
      step: 1,
    },
  },
  createdAtBefore: {
    component: FormikTextInput,
    props: {
      label: 'Created Before',
      type: 'datetime-local',
      step: 1,
    },
  },
};

export type ListAlertsFiltersValues = Pick<
  ListAlertsInput,
  | 'severity'
  | 'ruleId'
  | 'eventCountMin'
  | 'eventCountMax'
  | 'contains'
  | 'createdAtAfter'
  | 'createdAtBefore'
>;

const ListAlertsActions: React.FC = () => {
  const [areFiltersVisible, setFiltersVisibility] = React.useState(false);
  const { requestParams, updateRequestParams } = useRequestParamsWithInfiniteScroll<
    ListAlertsInput
  >();

  const filterKeys = Object.keys(filters) as (keyof ListAlertsInput)[];
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
    () => desanitizeDates(pick(requestParams, filterKeys) as ListAlertsFiltersValues),
    [requestParams]
  );

  return (
    <Box>
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
            <GenerateFiltersGroup<ListAlertsFiltersValues>
              filters={filters}
              onCancel={() => setFiltersVisibility(false)}
              onSubmit={newParams => updateRequestParams(sanitizeDates(newParams))}
              initialValues={initialFilterValues}
            />
          </Card>
        </ErrorBoundary>
      )}
    </Box>
  );
};

export default React.memo(ListAlertsActions);
