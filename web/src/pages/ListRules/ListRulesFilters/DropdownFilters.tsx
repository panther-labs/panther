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
import { Field, Form, Formik } from 'formik';
import { Box, Button, Card, Flex, Popover, PopoverContent, PopoverTrigger } from 'pouncejs';
import { ListRulesInput, SeverityEnum } from 'Generated/schema';
import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import isUndefined from 'lodash/isUndefined';
import { capitalize } from 'Helpers/utils';
import TextButton from 'Components/buttons/TextButton';
import FormikCombobox from 'Components/fields/ComboBox';

export type ListAlertsDropdownFiltersValues = Pick<ListRulesInput, 'severity' | 'enabled'>;

const severityOptions = Object.values(SeverityEnum);

const defaultValues = {
  severity: null,
  enabled: null,
};

const DropdownFilters: React.FC = () => {
  const { requestParams, updateRequestParamsAndResetPaging } = useRequestParamsWithPagination<
    ListRulesInput
  >();

  const initialDropdownFilters = React.useMemo(
    () =>
      ({
        ...defaultValues,
        ...requestParams,
      } as ListAlertsDropdownFiltersValues),
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
            aria-label="Rule Options"
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
              data-testid="dropdown-rule-listing-filters"
            >
              <Formik<ListAlertsDropdownFiltersValues>
                enableReinitialize
                onSubmit={(values: ListAlertsDropdownFiltersValues) => {
                  updateRequestParamsAndResetPaging(values);
                }}
                initialValues={initialDropdownFilters}
              >
                {({ setValues }) => (
                  <Form>
                    <Box pb={4}>
                      <Field
                        name="severity"
                        as={FormikCombobox}
                        items={['', ...severityOptions]}
                        itemToString={(severity: SeverityEnum | '') =>
                          severity === '' ? 'All' : capitalize(severity.toLowerCase())
                        }
                        label="Severity"
                        placeholder="Select a severity"
                      />
                    </Box>
                    <Box pb={4}>
                      <Field
                        name="enabled"
                        as={FormikCombobox}
                        items={[true, false]}
                        itemToString={(item: boolean) => (item ? 'Yes' : 'No')}
                        label="Enabled"
                        placeholder="Only show enabled rules?"
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
