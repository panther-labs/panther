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
import { LogAnalysisMetricsInput } from 'Generated/schema';
import { Flex, Box } from 'pouncejs';
import useRequestParamsWithoutPagination from 'Hooks/useRequestParamsWithoutPagination';
import FormikDateRangeInput from 'Components/fields/DateRangeInput';
import FormikCombobox from 'Components/fields/ComboBox';
import FormikAutosave from 'Components/utils/Autosave';
import { minutesToString } from 'Helpers/utils';

export type AlertsOverviewFiltersValues = Pick<
  LogAnalysisMetricsInput,
  'fromDate' | 'toDate' | 'intervalMinutes'
>;

const intervalMinutesOptions = [15, 30, 60, 180, 720, 1440];

interface AlertsOverviewFiltersProps {
  initialValues: AlertsOverviewFiltersValues;
}

const AlertsOverviewFilters: React.FC<AlertsOverviewFiltersProps> = ({ initialValues }) => {
  const { updateRequestParams } = useRequestParamsWithoutPagination<LogAnalysisMetricsInput>();

  return (
    <Flex
      justify="flex-end"
      position="absolute"
      right={0}
      pb={6}
      zIndex={1}
      transform="translateY(-100%)"
    >
      <Formik<AlertsOverviewFiltersValues>
        initialValues={initialValues}
        onSubmit={updateRequestParams}
      >
        <Form>
          <FormikAutosave threshold={50} />
          <Flex spacing={4} maxWidth={500}>
            <Box maxWidth={100}>
              <Field
                as={FormikCombobox}
                variant="solid"
                label="Interval"
                name="intervalMinutes"
                items={intervalMinutesOptions}
                itemToString={minutesToString}
              />
            </Box>
            <FormikDateRangeInput
              alignment="right"
              withPresets
              withTime
              variant="solid"
              format="MM/DD/YYYY HH:mm"
              labelStart="Date Start"
              labelEnd="Date End"
              placeholderStart="MM/DD/YY HH:mm"
              placeholderEnd="MM/DD/YY HH:mm"
              nameStart="fromDate"
              nameEnd="toDate"
            />
          </Flex>
        </Form>
      </Formik>
    </Flex>
  );
};

export default React.memo(AlertsOverviewFilters);
