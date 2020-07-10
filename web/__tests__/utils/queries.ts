import { queryHelpers, buildQueries, Matcher, MatcherOptions } from '@testing-library/react';

// Builds custom queries based on aria-attribute selectors
const buildQueryForAriaAttribute = (ariaAttribute: string) => {
  const queryAllByAriaAttribute = (...args) =>
    queryHelpers.queryAllByAttribute(
      'ariaAttribute',
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
