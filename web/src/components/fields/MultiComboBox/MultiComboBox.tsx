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
import { Box, FormError, MultiCombobox, MultiComboboxProps } from 'pouncejs';
import { FieldConfig } from 'formik';
import useFastField from 'Hooks/useFastField';

function FormikMultiCombobox<T>(
  props: MultiComboboxProps<T> & Required<Pick<FieldConfig, 'name'>>
): React.ReactNode {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [field, meta, { setValue }] = useFastField(props.name);

  const isInvalid = meta.touched && !!meta.error;
  const errorElementId = isInvalid ? `${props.name}-error` : undefined;

  return (
    <Box>
      <MultiCombobox
        {...props}
        invalid={isInvalid}
        aria-describedby={isInvalid ? errorElementId : undefined}
        onChange={setValue}
      />
      {isInvalid && (
        <FormError mt={2} id={errorElementId}>
          {meta.error}
        </FormError>
      )}
    </Box>
  );
}

export default FormikMultiCombobox;
