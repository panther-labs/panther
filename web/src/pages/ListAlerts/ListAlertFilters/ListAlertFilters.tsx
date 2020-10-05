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
import { Form, Formik, FastField } from 'formik';
import { Box, Flex } from 'pouncejs';
import {
  ListAlertsInput,
  SeverityEnum,
  AlertStatusesEnum,
  SortDirEnum,
  ListAlertsSortFieldsEnum,
} from 'Generated/schema';
import useRequestParamsWithoutPagination from 'Hooks/useRequestParamsWithoutPagination';
import { capitalize } from 'Helpers/utils';
import pick from 'lodash/pick';
import FormikAutosave from 'Components/utils/Autosave';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import FormikCombobox from 'Components/fields/ComboBox';
import FormikTextInput from 'Components/fields/TextInput';

export type ListAlertsInlineFiltersValues = Pick<
  ListAlertsInput,
  'severity' | 'status' | 'nameContains' | 'sortBy' | 'sortDir'
>;
export type SortingOptions = {
  opt: string;
  resolution: ListAlertsInput;
}[];

const severityOptions = Object.values(SeverityEnum);
const statusOptions = Object.values(AlertStatusesEnum);

const filterItemToString = (item: SeverityEnum | AlertStatusesEnum) =>
  capitalize(item.toLowerCase());

const filters = [
  'severity',
  'status',
  'nameContains',
  'sortBy',
  'sortDir',
  'eventCountMin',
  'eventCountMax',
] as (keyof ListAlertsInput)[];

const defaultValues = {
  nameContains: '',
  sorting: undefined,
  severity: [],
  status: [],
};

const sortingOpts: SortingOptions = [
  {
    opt: 'Most Recent',
    resolution: {
      sortBy: 'createdAt' as ListAlertsSortFieldsEnum,
      sortDir: 'descending' as SortDirEnum,
    },
  },
  {
    opt: 'Oldest',
    resolution: {
      sortBy: 'createdAt' as ListAlertsSortFieldsEnum,
      sortDir: 'ascending' as SortDirEnum,
    },
  },
];

/**
 * Since sorting is not responding to some ListAlertsInput key we shall exctract
 * this information from `sortBy` and `sortDir` parameters in order to align the
 * combobox values.
 */
const extractSortingOpts = params => {
  const { sorting, ...rest } = params;
  const sortingParams = sortingOpts.find(param => param.opt === sorting);
  return {
    ...rest,
    ...(sortingParams ? { ...sortingParams.resolution } : {}),
  };
};

const wrapSortingOptions = params => {
  const { sortBy, sortDir, ...rest } = params;
  const option = sortingOpts.find(
    param => param.resolution.sortBy === sortBy && param.resolution.sortDir === sortDir
  );

  return {
    ...(option ? { sorting: option.opt } : {}),
    ...rest,
  };
};

const ListAlertFilters: React.FC = () => {
  const { requestParams, updateRequestParams } = useRequestParamsWithoutPagination<
    ListAlertsInput
  >();

  const initialFilterValues = React.useMemo(
    () =>
      ({
        ...defaultValues,
        ...wrapSortingOptions(pick(requestParams, filters)),
      } as ListAlertsInlineFiltersValues),
    [requestParams]
  );

  return (
    <Flex justify="flex-end" align="center">
      <Formik<ListAlertsInlineFiltersValues>
        initialValues={initialFilterValues}
        onSubmit={(values: ListAlertsInlineFiltersValues) => {
          updateRequestParams(extractSortingOpts(values));
        }}
      >
        <Form>
          <FormikAutosave threshold={200} />
          <Flex spacing={4} align="center">
            <Box width={220}>
              <FastField
                name="nameContains"
                icon="search"
                iconAlignment="left"
                as={FormikTextInput}
                label="Filter Alerts by text"
              />
            </Box>
            <Box width={110}>
              <FastField
                name="eventCountMin"
                as={FormikTextInput}
                type="number"
                min={0}
                label="Max Events"
              />
            </Box>
            <Box width={110}>
              <FastField
                min={1}
                type="number"
                name="eventCountMax"
                as={FormikTextInput}
                label="Min Events"
              />
            </Box>
            <Box width={112}>
              <FastField
                name="severity"
                as={FormikMultiCombobox}
                items={severityOptions}
                itemToString={filterItemToString}
                label="Severity"
              />
            </Box>
            <Box maxWidth={112}>
              <FastField
                name="status"
                as={FormikMultiCombobox}
                items={statusOptions}
                itemToString={filterItemToString}
                label="Status"
              />
            </Box>
            <Box>
              <FastField
                name="sorting"
                as={FormikCombobox}
                items={sortingOpts.map(sortingOption => sortingOption.opt)}
                itemToString={filterItemToString}
                label="Sort By"
              />
            </Box>
          </Flex>
        </Form>
      </Formik>
    </Flex>
  );
};

export default React.memo(ListAlertFilters);
