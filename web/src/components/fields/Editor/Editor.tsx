/**
 * A Cloud-Native SIEM for the Modern Security Team
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
import Editor, { EditorProps } from 'Components/Editor';
import { useFormikContext, FieldConfig } from 'formik';
import debounce from 'lodash-es/debounce';

const FormikEditor: React.FC<EditorProps & Required<Pick<FieldConfig, 'name'>>> = ({
  // we destruct `onBlur` since we shouldn't pass it as a prop to `Editor`. This is becase we are
  // manually syncing the changes of the editor to the formik instance through the
  // `syncValueFromEditor`. Thus, we don't need an `onBlur`
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  onBlur,
  ...rest
}) => {
  const { setFieldValue } = useFormikContext<any>();

  // For performance enhancing reasons, we are debouncing the syncing of the editor value to
  // the formik controller. The editor is *not* a controlled component by nature, so we are
  // only syncing its internal state to formik with some delays.
  // It's worth noting that this is contradictory to all the other components in the `fields`
  // folder, since they are controlled
  const syncValueFromEditor = React.useCallback(
    debounce((value: string) => {
      setFieldValue(rest.name, value);
    }, 200),
    [setFieldValue, rest.name]
  );

  return <Editor {...rest} onChange={syncValueFromEditor} />;
};

export default FormikEditor;
