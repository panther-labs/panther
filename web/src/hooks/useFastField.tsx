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
import { useField, FieldHookConfig, FieldHelperProps } from 'formik';

/**
 * The current `useField` from formik is not performance oriented. We have raised this in an issue
 * but there this is still not fixed. This is a temporary workaround which will solve perf issues in
 * big complex forms
 * FIXME: Remove and replace with `useField` when perf issues are gone (i.e. issue below is closed)
 * https://github.com/jaredpalmer/formik/issues/2268
 */
function useFastField<Val = any>(
  propsOrFieldName: string | FieldHookConfig<Val>
): ReturnType<typeof useField> {
  const [field, meta, helpers] = useField<Val>(propsOrFieldName);

  const memoizedHelpersRef = React.useRef<{
    memoizedHelpers?: FieldHelperProps<Val>;
    memoizedSetValue?: FieldHelperProps<Val>['setValue'];
    memoizedsetTouched?: FieldHelperProps<Val>['setTouched'];
    memoizedsetError?: FieldHelperProps<Val>['setError'];
  }>({});

  // On every render, we save the newest helpers to memoizedHelpersRef, overriding the "function"
  // assigned to `setValue`, `setTouched` and `setError` accordingly, without losing referential
  // integrity
  memoizedHelpersRef.current.memoizedSetValue = helpers.setValue;
  memoizedHelpersRef.current.memoizedsetTouched = helpers.setTouched;
  memoizedHelpersRef.current.memoizedsetError = helpers.setError;

  // On the first render (where `memoizedHelpers` is undefined), we create a "referentially stable"
  // copy of formik's helpers. From now on, `setValue`, `setTouched` and `setError` will have the
  // same reference, but the functionn assigned to them will change on every render.
  if (!memoizedHelpersRef.current.memoizedHelpers) {
    memoizedHelpersRef.current.memoizedHelpers = {
      setValue: (...args) => memoizedHelpersRef.current.memoizedSetValue(...args),
      setTouched: (...args) => memoizedHelpersRef.current.memoizedsetTouched(...args),
      setError: (...args) => memoizedHelpersRef.current.memoizedsetError(...args),
    };
  }

  return [field, meta, memoizedHelpersRef.current.memoizedHelpers];
}

export default useFastField;
