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
import { Radio, RadioProps } from 'pouncejs';
import { FieldConfig, useField } from 'formik';

const FormikRadio: React.FC<RadioProps & Required<Pick<FieldConfig, 'name' | 'value'>>> = props => {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [field, meta, { setValue}] = useField(props.name);

  // Here `props.value` is the value that the radio button should have according to the typical HTML
  // and not the value that will be forced into Formik
  return (
    <Radio
      {...props}
      checked={field.value === props.value}
      onChange={setValue}
    />
  );
};

export default FormikRadio;
