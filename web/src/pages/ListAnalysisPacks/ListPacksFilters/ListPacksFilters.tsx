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
import { ListAnalysisPacksInput } from 'Generated/schema';
import { Box, Flex } from 'pouncejs';
import pick from 'lodash/pick';
import useRequestParamsWithoutPagination from 'Hooks/useRequestParamsWithoutPagination';
import FormikAutosave from 'Components/utils/Autosave';
import FormikTextInput from 'Components/fields/TextInput';
import DropdownFilters from './DropdownFilters';

export type ListPackInlineFiltersValues = Pick<ListAnalysisPacksInput, 'nameContains'>;

const filters = ['nameContains'] as (keyof ListAnalysisPacksInput)[];

const defaultValues = {
  nameContains: '',
};

const ListPacksFilters: React.FC = () => {
  const { requestParams, updateRequestParams } = useRequestParamsWithoutPagination<
    ListAnalysisPacksInput
  >();

  const initialFilterValues = React.useMemo(
    () =>
      ({
        ...defaultValues,
        ...pick(requestParams, filters),
      } as ListPackInlineFiltersValues),
    [requestParams]
  );

  return (
    <Flex justify="flex-end" align="center">
      <Formik<ListPackInlineFiltersValues>
        enableReinitialize
        initialValues={initialFilterValues}
        onSubmit={updateRequestParams}
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
                label="Filter Pack by text"
                placeholder="Search for a pack..."
              />
            </Box>
          </Flex>
        </Form>
      </Formik>
      <Box pr={4}>
        <DropdownFilters />
      </Box>
    </Flex>
  );
};

export default React.memo(ListPacksFilters);
