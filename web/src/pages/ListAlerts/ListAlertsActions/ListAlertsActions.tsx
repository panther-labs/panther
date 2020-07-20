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
import { capitalize, formatTime } from 'Helpers/utils';
import FormikTextInput from 'Components/fields/TextInput';
import useRequestParamsWithoutPagination from 'Hooks/useRequestParamsWithoutPagination';
import { Box, Button, Card, Collapse, Flex } from 'pouncejs';
import ErrorBoundary from 'Components/ErrorBoundary';
import isEmpty from 'lodash/isEmpty';
import isNumber from 'lodash/isNumber';
import pick from 'lodash/pick';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';

const severityOptions = Object.values(SeverityEnum);

export const filters = {
  severity: {
    component: FormikMultiCombobox,
    props: {
      label: 'Severity',
      items: severityOptions,
      itemToString: (severity: SeverityEnum) => capitalize(severity.toLowerCase()),
      placeholder: 'Choose a severity...',
    },
  },
  nameContains: {
    component: FormikTextInput,
    props: {
      label: 'Title',
      placeholder: 'Enter an alert title...',
    },
  },
  createdAtAfter: {
    component: FormikTextInput,
    props: {
      label: 'Date Start',
      placeholder: 'YYYY-MM-DDTHH:mm:ss',
      height: 46,
      onFocus: (e: React.FocusEvent<HTMLInputElement>) => {
        e.target.type = 'datetime-local';
      },
      onBlur: (e: React.FocusEvent<HTMLInputElement>) => {
        e.target.type = 'text';
      },
    },
  },
  createdAtBefore: {
    component: FormikTextInput,
    props: {
      label: 'Date End',
      placeholder: 'YYYY-MM-DDTHH:mm:ss',
      height: 46,
      onFocus: (e: React.FocusEvent<HTMLInputElement>) => {
        e.target.type = 'datetime-local';
      },
      onBlur: (e: React.FocusEvent<HTMLInputElement>) => {
        e.target.type = 'text';
      },
    },
  },
  ruleIdContains: {
    component: FormikTextInput,
    props: {
      label: 'Rule',
      placeholder: 'Enter a rule ID...',
    },
  },
  alertIdContains: {
    component: FormikTextInput,
    props: {
      label: 'Alert',
      placeholder: 'Enter an alert ID...',
    },
  },
  eventCountMin: {
    component: FormikTextInput,
    props: {
      label: 'Event Count (min)',
      placeholder: 'Enter a number...',
      type: 'number',
      min: 0,
    },
  },
  eventCountMax: {
    component: FormikTextInput,
    props: {
      label: 'Event Count (max)',
      placeholder: 'Enter a number...',
      type: 'number',
      min: 1,
    },
  },
};

export type ListAlertsFiltersValues = Pick<
  ListAlertsInput,
  | 'severity'
  | 'nameContains'
  | 'createdAtAfter'
  | 'createdAtBefore'
  | 'ruleIdContains'
  | 'alertIdContains'
  | 'eventCountMin'
  | 'eventCountMax'
>;

type ListAlertsActionsProps = {
  showActions: boolean;
};

// Keys that we know will use a date string format
const dateKeys = ['createdAtAfter', 'createdAtBefore'];

// Creates a datetime formatter to use based on the dayjs format
const createFormat = (format: string): any => formatTime(format);
const postFormatter = createFormat('YYYY-MM-DDTHH:mm:ss[Z]');
const preFormatter = createFormat('YYYY-MM-DDTHH:mm:ss');

// Checks every key in an object for date-like values and converts them to a desired format
const sanitizeDates = (formatter: any, utcIn?: boolean, utcOut?: boolean) => (
  parms: Partial<any>
) =>
  Object.entries(parms).reduce((acc, [k, v]) => {
    if (dateKeys.includes(k) && Date.parse(v)) {
      acc[k] = formatter(v, utcIn, utcOut);
      return acc;
    }
    acc[k] = v;
    return acc;
  }, {});

// These are needed to marshal UTC timestamps in the format the backend requires
// Create a formatter for date form field submit (local) -> URL parameter (UTC)
const postProcessDate = sanitizeDates(postFormatter, false, true);
// Create a formatter for URL parameter (UTC) -> date form field (local)
const preProcessDate = sanitizeDates(preFormatter, true, false);

const ListAlertsActions: React.FC<ListAlertsActionsProps> = ({ showActions }) => {
  const [areFiltersVisible, setFiltersVisibility] = React.useState(false);
  const { requestParams, updateRequestParams } = useRequestParamsWithoutPagination<
    ListAlertsInput
  >();

  // Get all of the keys we can filter by
  const filterKeys = Object.keys(filters) as (keyof ListAlertsInput)[];
  // Define a partial which will filter out URL params against our keys
  const filterValid = (key: keyof ListAlertsInput) =>
    !isEmpty(requestParams[key]) || isNumber(requestParams[key]);
  // Get the number of valid filters present in the URL params
  const filtersCount = filterKeys.filter(filterValid).length;

  // If there is at least one filter set visibility to true
  // -or- if there's an override
  React.useEffect(() => {
    if (filtersCount > 0 || showActions) {
      setFiltersVisibility(true);
    }
  }, [filtersCount, showActions]);

  // The initial filter values for when the filters component first renders. If you see down below,
  // we mount and unmount it depending on whether it's visible or not
  const initialFilterValues = React.useMemo(
    () => preProcessDate(pick(requestParams, filterKeys) as ListAlertsFiltersValues),
    [requestParams]
  );

  return (
    <Box mb={6} as="section">
      <Flex justify="flex-end">
        <Button
          active={areFiltersVisible}
          icon="filter"
          variant="outline"
          variantColor="navyblue"
          onClick={() => setFiltersVisibility(!areFiltersVisible)}
        >
          Filter Options {filtersCount ? `(${filtersCount})` : ''}
        </Button>
      </Flex>
      <ErrorBoundary>
        <Collapse open={areFiltersVisible}>
          <Box pt={6}>
            <Card p={8}>
              <GenerateFiltersGroup<ListAlertsFiltersValues>
                filters={filters}
                onSubmit={newParams => updateRequestParams(postProcessDate(newParams))}
                initialValues={initialFilterValues}
              />
            </Card>
          </Box>
        </Collapse>
      </ErrorBoundary>
    </Box>
  );
};

export default React.memo(ListAlertsActions);
