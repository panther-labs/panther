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
import storage from 'Helpers/storage';

export interface UseFormSessionRestorationProps {
  /** Unique identifier for the "sessioned" values */
  sessionId: string;
}

/**
 * Helps save & restore form sessions when the user navigates away or closes the tab while making
 * changes
 */
function useFormSessionRestoration<FormValues>({ sessionId }: UseFormSessionRestorationProps) {
  const { values, dirty, setValues } = useFormikContext<FormValues>();

  React.useEffect(() => {
    const previousSessionValues = storage.session.read<FormValues>(sessionId);
    if (previousSessionValues) {
      setValues(previousSessionValues);
    }
  }, [sessionId, setValues]);

  React.useEffect(() => {
    if (dirty) {
      storage.session.write(sessionId, values);
    } else {
      storage.session.delete(sessionId);
    }
  }, [values, dirty]);
}

export default useFormSessionRestoration;
