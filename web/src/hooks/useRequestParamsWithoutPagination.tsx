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
import useUrlParams from 'Hooks/useUrlParams';

function useRequestParamsWithoutPagination<AvailableParams>() {
  const { urlParams, updateUrlParams, setUrlParams } = useUrlParams<Partial<AvailableParams>>();

  // This is our typical function that updates the parameters
  const updateRequestParams = React.useCallback(
    (newParams: Partial<AvailableParams>) => {
      updateUrlParams({ ...urlParams, ...newParams });
    },
    [urlParams]
  );

  // This is a similar function like the above but instead of updating the existing params with the
  // new parameters, it clears all the parameters and just sets the parameters passed as an argument
  const setRequestParams = React.useCallback(
    (newParams: Partial<AvailableParams>) => {
      setUrlParams({ ...newParams });
    },
    [urlParams]
  );

  return React.useMemo(
    () => ({
      requestParams: urlParams,
      updateRequestParams,
      setRequestParams,
    }),
    [urlParams]
  );
}
export default useRequestParamsWithoutPagination;
