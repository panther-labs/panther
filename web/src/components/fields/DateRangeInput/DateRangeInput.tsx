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
import { Box, FormError, DateRangeInput, DateRangeInputProps } from 'pouncejs';
import { useField } from 'formik';
import dayjs from 'dayjs';

const shiftOffset = (date: Date, operation: 'subtract' | 'add') => {
  const d = dayjs(date);
  const utcOffsetHours = d.utcOffset() / 60;
  const modifiedDate =
    operation === 'subtract' ? d.subtract(utcOffsetHours, 'hour') : d.add(utcOffsetHours, 'hour');

  return modifiedDate.toDate();
};

export interface FieldDateRangeInputProps
  extends Omit<DateRangeInputProps, 'name' | 'iconAlignment' | 'iconProps' | 'value' | 'onChange'> {
  nameStart: string;
  nameEnd: string;
  useUTC?: boolean;
}

const FormikDateRangeInput: React.FC<FieldDateRangeInputProps> = ({
  nameStart,
  nameEnd,
  useUTC = false,
  ...rest
}) => {
  const [, metaStart, helpersStart] = useField<string>(nameStart);
  const [, metaEnd, helpersEnd] = useField<string>(nameEnd);

  const { touched: touchedStart, error: errorStart, value: valueStart } = metaStart;
  const { setValue: setValueStart } = helpersStart;

  const { touched: touchedEnd, error: errorEnd, value: valueEnd } = metaEnd;
  const { setValue: setValueEnd } = helpersEnd;

  const touched = touchedStart || touchedEnd;
  const error = errorStart || errorEnd;

  const isInvalid = touched && !!error;

  const errorElementId = isInvalid ? `${nameStart}-${nameEnd}-error` : undefined;

  const value = React.useMemo(() => {
    // The last `.map` is an UGLY hack that's used as a workaround, to allow the date range picker
    // to display the same exact time that was used as an initial value (stripping the timezone).
    return [valueStart, valueEnd]
      .filter(Boolean)
      .map(val => (val ? new Date(val) : null))
      .map(date => (useUTC ? shiftOffset(date, 'subtract') : date));
  }, [valueStart, valueEnd, useUTC]);

  const onRangeChange = React.useCallback<DateRangeInputProps['onChange']>(
    ([start, end]) => {
      // This is an UGLY hack that's used as a workaround, to allow the date range picker to
      // allow the user to select values in UTC (currently the picker selects dates in the user'ss
      // timezone and this is something not configurable through a prop)
      const startDate = useUTC ? shiftOffset(start, 'add') : start;
      const endDate = useUTC ? shiftOffset(end, 'add') : end;

      setValueStart(startDate.toISOString());
      setValueEnd(endDate.toISOString());
    },
    [setValueStart, setValueEnd, useUTC]
  );

  return (
    <Box>
      <DateRangeInput
        {...rest}
        name={`${nameStart}-${nameEnd}`}
        invalid={isInvalid}
        value={value}
        onChange={onRangeChange}
      />
      {isInvalid && (
        <FormError mt={2} id={errorElementId}>
          {error}
        </FormError>
      )}
    </Box>
  );
};

export default FormikDateRangeInput;
