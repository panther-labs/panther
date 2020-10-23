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
import {
  Box,
  SimpleGrid,
  Button,
  Popover,
  PopoverTrigger,
  PopoverContent,
  Flex,
  Card,
} from 'pouncejs';
import { ListAlertsInput, SeverityEnum, AlertStatusesEnum } from 'Generated/schema';
import useRequestParamsWithoutPagination from 'Hooks/useRequestParamsWithoutPagination';
import { capitalize } from 'Helpers/utils';
import isEmpty from 'lodash/isEmpty';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import TextButton from 'Components/buttons/TextButton';
import FormikTextInput from 'Components/fields/TextInput';

export type ListAlertsDropdownFiltersValues = Pick<
  ListAlertsInput,
  'severity' | 'status' | 'eventCountMax' | 'eventCountMin'
>;

const filterItemToString = (item: SeverityEnum | AlertStatusesEnum) =>
  capitalize(item.toLowerCase());

const statusOptions = Object.values(AlertStatusesEnum);
const severityOptions = Object.values(SeverityEnum);

const defaultValues = {
  severity: [],
  status: [],
};

const DropdownFilters: React.FC = () => {
  const { requestParams, updateRequestParams } = useRequestParamsWithoutPagination<
    ListAlertsInput
  >();

  const initialDropdownFilters = React.useMemo(
    () =>
      ({
        ...defaultValues,
        ...requestParams,
      } as ListAlertsDropdownFiltersValues),
    [requestParams]
  );
  const filtersCount = Object.keys(defaultValues).filter(key => !isEmpty(requestParams[key]))
    .length;

  return (
    <Popover>
      {({ close: closePopover }) => (
        <React.Fragment>
          <PopoverTrigger
            as={Button}
            iconAlignment="right"
            icon="filter-light"
            aria-label="Additional Filters"
          >
            Filters {filtersCount ? `(${filtersCount})` : ''}
          </PopoverTrigger>
          <PopoverContent alignment="bottom-left">
            <Card shadow="dark300" my={14} p={6} pb={4} minWidth={425}>
              <Formik<ListAlertsDropdownFiltersValues>
                onSubmit={updateRequestParams}
                initialValues={initialDropdownFilters}
              >
                <Form>
                  <Box pb={4}>
                    <FastField
                      name="status"
                      as={FormikMultiCombobox}
                      items={statusOptions}
                      itemToString={filterItemToString}
                      label="Status"
                    />
                  </Box>
                  <Box pb={4}>
                    <FastField
                      name="severity"
                      as={FormikMultiCombobox}
                      items={severityOptions}
                      itemToString={filterItemToString}
                      label="Severity"
                    />
                  </Box>
                  <SimpleGrid columns={2} gap={4} pb={4}>
                    <FastField
                      name="eventCountMin"
                      as={FormikTextInput}
                      type="number"
                      min={0}
                      label="Min Events"
                    />
                    <FastField
                      name="eventCountMax"
                      as={FormikTextInput}
                      type="number"
                      min={0}
                      label="Max Events"
                    />
                  </SimpleGrid>
                  <Flex direction="column" justify="center" align="center" spacing={4}>
                    <Box>
                      <Button type="submit" onClick={closePopover}>
                        Apply Filters
                      </Button>
                    </Box>
                    <TextButton
                      role="button"
                      onClick={() => {
                        updateRequestParams(defaultValues);
                      }}
                    >
                      Clear All Filters
                    </TextButton>
                  </Flex>
                </Form>
              </Formik>
            </Card>
          </PopoverContent>
        </React.Fragment>
      )}
    </Popover>
  );
};

export default React.memo(DropdownFilters);
