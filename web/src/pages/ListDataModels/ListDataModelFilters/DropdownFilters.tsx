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
import { FastField, Field, Form, Formik } from 'formik';
import { Box, Button, Card, Flex, Popover, PopoverContent, PopoverTrigger } from 'pouncejs';
import { ListDataModelsInput } from 'Generated/schema';
import useRequestParamsWithoutPagination from 'Hooks/useRequestParamsWithoutPagination';
import isUndefined from 'lodash/isUndefined';
import TextButton from 'Components/buttons/TextButton';
import FormikCombobox from 'Components/fields/ComboBox';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import { useListAvailableLogTypes } from 'Source/graphql/queries';

export type ListDataModelsDropdownFiltersValues = Pick<ListDataModelsInput, 'logTypes' | 'enabled'>;

const defaultValues = {
  logTypes: [],
  enabled: null,
};

const enabledFilterToString = (item: boolean | string) => {
  if (item === '') {
    return 'All';
  }
  return item ? 'Yes' : 'No';
};

const DropdownFilters: React.FC = () => {
  const { data: logTypeData } = useListAvailableLogTypes();
  const { requestParams, updateRequestParams } = useRequestParamsWithoutPagination<
    ListDataModelsInput
  >();

  const initialDropdownFilters = React.useMemo(
    () =>
      ({
        ...defaultValues,
        ...requestParams,
      } as ListDataModelsDropdownFiltersValues),
    [requestParams]
  );

  const filtersCount = Object.keys(defaultValues).filter(key => !isUndefined(requestParams[key]))
    .length;

  return (
    <Popover>
      {({ close: closePopover }) => (
        <React.Fragment>
          <PopoverTrigger
            as={Button}
            iconAlignment="right"
            icon="filter-light"
            size="large"
            aria-label="Data Model Options"
          >
            Filters {filtersCount ? `(${filtersCount})` : ''}
          </PopoverTrigger>
          <PopoverContent>
            <Card
              shadow="dark300"
              my={14}
              p={6}
              pb={4}
              backgroundColor="navyblue-400"
              minWidth={425}
              data-testid="dropdown-data-model-listing-filters"
            >
              <Formik<ListDataModelsDropdownFiltersValues>
                enableReinitialize
                onSubmit={(values: ListDataModelsDropdownFiltersValues) => {
                  updateRequestParams(values);
                }}
                initialValues={initialDropdownFilters}
              >
                {({ setValues }) => (
                  <Form>
                    <Box pb={4}>
                      <Field
                        name="logTypes"
                        as={FormikMultiCombobox}
                        items={logTypeData?.listAvailableLogTypes?.logTypes ?? []}
                        label="Log Types"
                        placeholder="Select log types"
                      />
                    </Box>
                    <Box pb={4}>
                      <FastField
                        name="enabled"
                        as={FormikCombobox}
                        items={['', true, false]}
                        itemToString={enabledFilterToString}
                        label="Enabled"
                        placeholder="Only show enabled data models?"
                      />
                    </Box>

                    <Flex direction="column" justify="center" align="center" spacing={4}>
                      <Box>
                        <Button type="submit" onClick={closePopover}>
                          Apply Filters
                        </Button>
                      </Box>
                      <TextButton role="button" onClick={() => setValues(defaultValues)}>
                        Clear Filters
                      </TextButton>
                    </Flex>
                  </Form>
                )}
              </Formik>
            </Card>
          </PopoverContent>
        </React.Fragment>
      )}
    </Popover>
  );
};

export default React.memo(DropdownFilters);
