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
import urls from 'Source/urls';
import { Form, Formik, FastField } from 'formik';
import { SortDirEnum, ListRulesInput, ListRulesSortFieldsEnum } from 'Generated/schema';
import { Box, Flex } from 'pouncejs';
import pick from 'lodash/pick';
import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import FormikAutosave from 'Components/utils/Autosave';
import FormikCombobox from 'Components/fields/ComboBox';
import FormikTextInput from 'Components/fields/TextInput';
import LinkButton from 'Components/buttons/LinkButton';
import DropdownFilters from './DropdownFilters';

export type ListAlertsInlineFiltersValues = Pick<ListRulesInput, 'sortBy' | 'sortDir'>;

export type SortingOptions = {
  opt: string;
  resolution: ListRulesInput;
}[];

const filters = ['nameContains', 'sortBy', 'sortDir'] as (keyof ListRulesInput)[];

const defaultValues = {
  nameContains: '',
  sorting: undefined,
};

const sortingOpts: SortingOptions = [
  {
    opt: 'Most Recently Modified',
    resolution: {
      sortBy: 'lastModified' as ListRulesSortFieldsEnum,
      sortDir: 'descending' as SortDirEnum,
    },
  },
  {
    opt: 'Oldest Modified',
    resolution: {
      sortBy: 'lastModified' as ListRulesSortFieldsEnum,
      sortDir: 'ascending' as SortDirEnum,
    },
  },
  {
    opt: 'ID Ascending',
    resolution: {
      sortBy: 'id' as ListRulesSortFieldsEnum,
      sortDir: 'ascending' as SortDirEnum,
    },
  },
  {
    opt: 'ID Descending',
    resolution: {
      sortBy: 'id' as ListRulesSortFieldsEnum,
      sortDir: 'descending' as SortDirEnum,
    },
  },
  {
    opt: 'Severity Ascending',
    resolution: {
      sortBy: 'severity' as ListRulesSortFieldsEnum,
      sortDir: 'ascending' as SortDirEnum,
    },
  },
  {
    opt: 'Severity Descending',
    resolution: {
      sortBy: 'severity' as ListRulesSortFieldsEnum,
      sortDir: 'descending' as SortDirEnum,
    },
  },
  {
    opt: 'Status Ascending',
    resolution: {
      sortBy: 'status' as ListRulesSortFieldsEnum,
      sortDir: 'ascending' as SortDirEnum,
    },
  },
  {
    opt: 'Status Descending',
    resolution: {
      sortBy: 'status' as ListRulesSortFieldsEnum,
      sortDir: 'descending' as SortDirEnum,
    },
  },
  {
    opt: 'Log Types Ascending',
    resolution: {
      sortBy: 'logTypes' as ListRulesSortFieldsEnum,
      sortDir: 'ascending' as SortDirEnum,
    },
  },
  {
    opt: 'Log Types Descending',
    resolution: {
      sortBy: 'logTypes' as ListRulesSortFieldsEnum,
      sortDir: 'descending' as SortDirEnum,
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
  const { requestParams, updateRequestParamsAndResetPaging } = useRequestParamsWithPagination<
    ListRulesInput
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
          updateRequestParamsAndResetPaging(extractSortingOpts(values));
        }}
      >
        <Form>
          <FormikAutosave threshold={200} />
          <Flex spacing={4} align="center" pr={4}>
            <Box width={425}>
              <FastField
                name="nameContains"
                icon="search"
                iconAlignment="left"
                as={FormikTextInput}
                label="Filter Alerts by text"
              />
            </Box>
            <Box>
              <FastField
                name="sorting"
                as={FormikCombobox}
                items={sortingOpts.map(sortingOption => sortingOption.opt)}
                label="Sort By"
              />
            </Box>
          </Flex>
        </Form>
      </Formik>
      <Box pr={4}>
        <DropdownFilters />
      </Box>
      <LinkButton to={urls.logAnalysis.rules.create()}>Create New Rule</LinkButton>
    </Flex>
  );
};

export default React.memo(ListAlertFilters);
