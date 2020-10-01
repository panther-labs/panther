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
import { Box, FormError, TextInput, TextInputProps, Tooltip } from 'pouncejs';
import { FieldConfig, useField } from 'formik';
import { DEFAULT_SENSITIVE_VALUE } from 'Source/constants';

const iconProps: TextInputProps['iconProps'] = { color: 'violet-300' };

interface MaskedInputProps {
  shouldMask?: boolean;
}

export type SensitiveInputProps = TextInputProps & MaskedInputProps;

const FormikSensitiveTextInput: React.FC<
  SensitiveInputProps & Required<Pick<FieldConfig, 'name'>>
> = ({ shouldMask = true, ...props }) => {
  const [isFocused, setFocused] = React.useState(false);
  const [, meta] = useField(props.name);

  const { touched, error, value } = meta;
  const masked = value === '' && !isFocused && shouldMask;
  const isInvalid = touched && !!error;
  const errorElementId = isInvalid ? `${props.name}-error` : undefined;

  const onFocus = React.useCallback(() => {
    setFocused(true);
  }, [setFocused]);
  const onBlur = React.useCallback(() => {
    setFocused(false);
  }, [setFocused]);

  return (
    <Box>
      <Tooltip content="This information is sensitive and we hide it for your own protection">
        <Box position="relative">
          {/* 
            The Box above is used in order to bubble the focus events upwards. 
            The tooltip wrapping the sensitive text input stop the focus propagation.
          */}
          <TextInput
            {...props}
            autoComplete="off"
            onBlur={onBlur}
            onFocus={onFocus}
            invalid={isInvalid}
            aria-describedby={isInvalid ? errorElementId : undefined}
            value={masked ? DEFAULT_SENSITIVE_VALUE : value}
            type="password"
            icon="alert-circle-filled"
            iconProps={iconProps}
          />
        </Box>
      </Tooltip>
      {isInvalid && (
        <FormError mt={2} id={errorElementId}>
          {meta.error}
        </FormError>
      )}
    </Box>
  );
};

export default FormikSensitiveTextInput;
