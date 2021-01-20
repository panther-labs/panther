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

export type ListRulesInlineFiltersValues = Pick<ListRulesInput, 'sortBy' | 'sortDir'>;

export type SortingOptions = {
  opt: string;
  resolution: ListRulesInput;
}[];

const filters = ['nameContains', 'sortBy', 'sortDir'] as (keyof ListRulesInput)[];

const defaultValues = {
  nameContains: '',
  sorting: null,
};

const sortingOpts: SortingOptions = [
  {
    opt: 'Name Ascending',
    resolution: {
      sortBy: ListRulesSortFieldsEnum.DisplayName,
      sortDir: SortDirEnum.Ascending,
    },
  },
  {
    opt: 'Name Descending',
    resolution: {
      sortBy: ListRulesSortFieldsEnum.DisplayName,
      sortDir: SortDirEnum.Descending,
    },
  },
  {
    opt: 'Most Recently Modified',
    resolution: {
      sortBy: ListRulesSortFieldsEnum.LastModified,
      sortDir: SortDirEnum.Descending,
    },
  },
  {
    opt: 'Oldest Modified',
    resolution: {
      sortBy: ListRulesSortFieldsEnum.LastModified,
      sortDir: SortDirEnum.Ascending,
    },
  },
  {
    opt: 'Severity Ascending',
    resolution: {
      sortBy: ListRulesSortFieldsEnum.Severity,
      sortDir: SortDirEnum.Ascending,
    },
  },
  {
    opt: 'Severity Descending',
    resolution: {
      sortBy: ListRulesSortFieldsEnum.Severity,
      sortDir: SortDirEnum.Descending,
    },
  },
  {
    opt: 'Log Types Ascending',
    resolution: {
      sortBy: ListRulesSortFieldsEnum.LogTypes,
      sortDir: SortDirEnum.Ascending,
    },
  },
  {
    opt: 'Log Types Descending',
    resolution: {
      sortBy: ListRulesSortFieldsEnum.LogTypes,
      sortDir: SortDirEnum.Descending,
    },
  },
];

/**
 * Since sorting is not responding to some ListRulesInput key we shall extract
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

const ListRuleFilters: React.FC = () => {
  const { requestParams, updateRequestParamsAndResetPaging } = useRequestParamsWithPagination<
    ListRulesInput
  >();
  const initialFilterValues = React.useMemo(
    () =>
      ({
        ...defaultValues,
        ...wrapSortingOptions(pick(requestParams, filters)),
      } as ListRulesInlineFiltersValues),
    [requestParams]
  );
  return (
    <Flex justify="flex-end" align="center">
      <Formik<ListRulesInlineFiltersValues>
        enableReinitialize
        initialValues={initialFilterValues}
        onSubmit={(values: ListRulesInlineFiltersValues) => {
          updateRequestParamsAndResetPaging(extractSortingOpts(values));
        }}
      >
        <Form>
          <FormikAutosave threshold={200} />
          <Flex spacing={4} align="center" pr={4}>
            <Box minWidth={425}>
              <FastField
                name="nameContains"
                icon="search"
                iconAlignment="left"
                as={FormikTextInput}
                label="Filter Rules by text"
                placeholder="Search for a rule..."
              />
            </Box>
            <Box minWidth={220}>
              <FastField
                name="sorting"
                as={FormikCombobox}
                items={sortingOpts.map(sortingOption => sortingOption.opt)}
                label="Sort By"
                placeholder="Select a sort option"
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

export default React.memo(ListRuleFilters);
