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
import { useFormikContext } from 'formik';
import debounce from 'lodash/debounce';

export interface AutosaveProps {
  threshold?: number;
}

const FormikAutosave: React.FC<AutosaveProps> = ({ threshold = 0 }) => {
  const { submitForm, values } = useFormikContext();
  const isInitialMount = React.useRef(true);

  const debouncedSubmit = React.useCallback(
    debounce(() => {
      submitForm();
    }, threshold),
    [threshold, submitForm]
  );

  React.useEffect(() => {
    if (isInitialMount.current) {
      isInitialMount.current = false;
    } else {
      debouncedSubmit();
    }
  }, [debouncedSubmit, values]);

  return null;
};

export default FormikAutosave;
