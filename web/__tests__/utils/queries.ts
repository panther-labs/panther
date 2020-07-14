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

import { queryHelpers, buildQueries, Matcher, MatcherOptions } from '@testing-library/react';

// Builds custom queries based on aria-attribute selectors
const buildQueryForAriaAttribute = (ariaAttribute: string) => {
  const queryAllByAriaAttribute = (...args) =>
    queryHelpers.queryAllByAttribute(
      ariaAttribute,
      ...(args as [HTMLElement, Matcher, MatcherOptions])
    );

  const getMultipleError = (container: HTMLElement, ariaAttributeValue) =>
    `Found multiple elements with the ${ariaAttribute} attribute of: ${ariaAttributeValue}`;

  const getMissingError = (container: HTMLElement, ariaAttributeValue) =>
    `Unable to find an element with the ${ariaAttribute} attribute of: ${ariaAttributeValue}`;

  return buildQueries(queryAllByAriaAttribute, getMultipleError, getMissingError);
};

const [
  queryByAriaLabel,
  getAllByAriaLabel,
  getByAriaLabel,
  findAllByAriaLabel,
  findByAriaLabel,
] = buildQueryForAriaAttribute('aria-label');

export { queryByAriaLabel, getAllByAriaLabel, getByAriaLabel, findAllByAriaLabel, findByAriaLabel };
