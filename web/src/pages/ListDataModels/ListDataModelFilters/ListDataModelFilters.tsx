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
import { SortDirEnum, ListDataModelsInput, ListDataModelsSortFieldsEnum } from 'Generated/schema';
import { Box, Flex } from 'pouncejs';
import pick from 'lodash/pick';
import useRequestParamsWithoutPagination from 'Hooks/useRequestParamsWithoutPagination';
import FormikAutosave from 'Components/utils/Autosave';
import FormikCombobox from 'Components/fields/ComboBox';
import FormikTextInput from 'Components/fields/TextInput';
import LinkIconButton from 'Components/buttons/LinkIconButton';
import DropdownFilters from './DropdownFilters';

export type ListDataModelInlineFiltersValues = Pick<ListDataModelsInput, 'sortBy' | 'sortDir'>;

export type SortingOptions = {
  opt: string;
  resolution: ListDataModelsInput;
}[];

const filters = ['nameContains', 'sortBy', 'sortDir'] as (keyof ListDataModelsInput)[];

const defaultValues = {
  nameContains: '',
  sorting: null,
};

const sortingOpts: SortingOptions = [
  {
    opt: 'Id (A-Z)',
    resolution: {
      sortBy: ListDataModelsSortFieldsEnum.Id,
      sortDir: SortDirEnum.Ascending,
    },
  },
  {
    opt: 'Id (Z-A)',
    resolution: {
      sortBy: ListDataModelsSortFieldsEnum.Id,
      sortDir: SortDirEnum.Descending,
    },
  },
  {
    opt: 'Most Recent',
    resolution: {
      sortBy: ListDataModelsSortFieldsEnum.LastModified,
      sortDir: SortDirEnum.Descending,
    },
  },
  {
    opt: 'Oldest',
    resolution: {
      sortBy: ListDataModelsSortFieldsEnum.LastModified,
      sortDir: SortDirEnum.Ascending,
    },
  },
];

/**
 * Since sorting is not responding to some ListDataModelsInput key we shall extract
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

const ListDataModelFilters: React.FC = () => {
  const { requestParams, updateRequestParams } = useRequestParamsWithoutPagination<
    ListDataModelsInput
  >();

  const initialFilterValues = React.useMemo(
    () =>
      ({
        ...defaultValues,
        ...wrapSortingOptions(pick(requestParams, filters)),
      } as ListDataModelInlineFiltersValues),
    [requestParams]
  );

  return (
    <Flex justify="flex-end" align="center">
      <Formik<ListDataModelInlineFiltersValues>
        enableReinitialize
        initialValues={initialFilterValues}
        onSubmit={(values: ListDataModelInlineFiltersValues) => {
          updateRequestParams(extractSortingOpts(values));
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
                label="Filter Data Models by text"
                placeholder="Search for a data model..."
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
      <LinkIconButton
        icon="add-circle"
        aria-label="Add a new Data Model"
        to={urls.logAnalysis.dataModels.create()}
      />
    </Flex>
  );
};

export default React.memo(ListDataModelFilters);
