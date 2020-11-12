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
import useRouter from 'Hooks/useRouter';
import queryString from 'query-string';
import omitBy from 'lodash/omitBy';

export const queryStringOptions = {
  arrayFormat: 'bracket' as const,
  parseNumbers: true,
  parseBooleans: true,
};

function useUrlParams<T extends { [key: string]: any }>() {
  const { history, location } = useRouter();

  /**
   * parses the query params of a URL and returns an object with params in the correct typo
   */
  const urlParams = queryString.parse(location.search, queryStringOptions) as T;

  /**
   * stringifies an object and adds it to the existing query params of a URL
   */
  const updateUrlParams = (params: Partial<T>) => {
    const mergedQueryParams = {
      ...urlParams,
      ...params,
    };

    // Remove any falsy value apart from the value `0` (number) and the value `false` (boolean)
    const cleanedMergedQueryParams = omitBy(
      mergedQueryParams,
      v => !v && !['number', 'boolean'].includes(typeof v)
    );

    history.replace({
      ...location,
      search: queryString.stringify(cleanedMergedQueryParams, queryStringOptions),
    });
  };

  /**
   * stringifies an object and replaces the query params of a URL
   */
  const setUrlParams = (params: Partial<T>) => {
    // Remove any falsy value apart from the value `0` (number) and the value `false` (boolean)
    const cleanedQueryParams = omitBy(params, v => !v && !['number', 'boolean'].includes(typeof v));

    history.replace({
      ...location,
      search: queryString.stringify(cleanedQueryParams, queryStringOptions),
    });
  };

  // Cache those values as long as URL parameters are the same
  return React.useMemo(
    () => ({
      urlParams,
      updateUrlParams,
      setUrlParams,
    }),
    [history.location.search]
  );
}

export default useUrlParams;
