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
import { formatTime } from 'Helpers/utils';
import isEmpty from 'lodash/isEmpty';
import { useField } from 'formik';

export interface FieldDateRangeInputProps
  extends Omit<DateRangeInputProps, 'name' | 'iconAlignment' | 'iconProps' | 'value' | 'onChange'> {
  nameStart: string;
  nameEnd: string;
}

const postFormatter = formatTime('YYYY-MM-DDTHH:mm:ss[Z]');
const preFormatter = formatTime('YYYY-MM-DDTHH:mm:ss');

const FormikDateRangeInput: React.FC<FieldDateRangeInputProps> = ({
  nameStart,
  nameEnd,
  ...rest
}) => {
  const [, metaStart, helpersStart] = useField(nameStart);
  const [, metaEnd, helpersEnd] = useField(nameEnd);

  const { touched: touchedStart, error: errorStart, value: valueStart } = metaStart;
  const { setValue: setValueStart } = helpersStart;

  const { touched: touchedEnd, error: errorEnd, value: valueEnd } = metaEnd;
  const { setValue: setValueEnd } = helpersEnd;

  const isInvalid = (touchedStart || touchedEnd) && (!!errorStart || !!errorEnd);

  const errorElementId = isInvalid ? `${nameStart}-${nameEnd}-error` : undefined;

  const value = React.useMemo(() => {
    return [valueStart, valueEnd].map(date => {
      if (date) {
        return preFormatter(date, true, false);
      }
      return date;
    });
  }, [valueStart, valueEnd]);

  const onRangeChange = React.useCallback(
    ([start, end]) => {
      setValueStart(postFormatter(start, false, true));
      setValueEnd(postFormatter(end, false, true));
    },
    [setValueStart, setValueEnd]
  );

  const error = React.useMemo(() => {
    if (!isEmpty(errorStart)) {
      return errorStart;
    }
    if (!isEmpty(errorEnd)) {
      return errorEnd;
    }
    return null;
  }, [isInvalid]);

  return (
    <Box>
      <DateRangeInput
        name={`${nameStart}-${nameEnd}`}
        invalid={isInvalid}
        {...rest}
        value={value}
        onChange={onRangeChange}
      />
      {isInvalid && error && (
        <FormError mt={2} id={errorElementId}>
          {error}
        </FormError>
      )}
    </Box>
  );
};

export default FormikDateRangeInput;
