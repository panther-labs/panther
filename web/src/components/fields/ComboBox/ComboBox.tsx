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
import { Combobox, ComboboxProps, FormError } from 'pouncejs';
import { FieldConfig, useField } from 'formik';

function FormikCombobox<T>(
  props: ComboboxProps<T> & Required<Pick<FieldConfig, 'name'>>
): React.ReactNode {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [field, meta, { setValue }] = useField(props.name);

  const isInvalid = meta.touched && !!meta.error;
  const errorElementId = isInvalid ? `${props.name}-error` : undefined;

  return (
    <React.Fragment>
      <Combobox
        {...props}
        invalid={isInvalid}
        aria-describedby={errorElementId}
        onChange={setValue}
      />
      {isInvalid && (
        <FormError mt={2} id={errorElementId}>
          {meta.error}
        </FormError>
      )}
    </React.Fragment>
  );
}

export default FormikCombobox;
