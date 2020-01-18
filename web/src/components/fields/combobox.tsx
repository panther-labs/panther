/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
import { Combobox, ComboboxProps } from 'pouncejs';
import { useFormikContext, FieldConfig } from 'formik';

function FormikCombobox<T>(
  props: ComboboxProps<T> & Required<Pick<FieldConfig, 'name'>>
): React.ReactNode {
  const { setFieldValue } = useFormikContext<any>();
  return <Combobox<T> {...props} onChange={value => setFieldValue(props.name, value)} />;
}

export default FormikCombobox;
