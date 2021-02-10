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

import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';

import * as Yup from 'yup';
import {
  ActiveSuppressCount,
  AlertTypesEnum,
  ComplianceIntegration,
  ComplianceStatusCounts,
  OrganizationReportBySeverity,
  ScannedResources,
} from 'Generated/schema';
import {
  INCLUDE_DIGITS_REGEX,
  INCLUDE_LOWERCASE_REGEX,
  INCLUDE_SPECIAL_CHAR_REGEX,
  INCLUDE_UPPERCASE_REGEX,
  CHECK_IF_HASH_REGEX,
  SOURCE_LABEL_REGEX,
} from 'Source/constants';
import sum from 'lodash/sum';
import { ErrorResponse } from 'apollo-link-error';
import { ApolloError } from '@apollo/client';
import { UserDetails } from 'Source/graphql/fragments/UserDetails.generated';

export const isMobile = /Mobi|Android/i.test(navigator.userAgent);

// Generate a new secret code that contains metadata of issuer and user email
export const formatSecretCode = (code: string, email: string): string => {
  const issuer = 'Panther';
  return `otpauth://totp/${issuer}:${email}?secret=${code}&issuer=${issuer}`;
};

export const getArnRegexForService = (awsService: string) => {
  return new RegExp(`arn:aws:${awsService.toLowerCase()}:([a-z]){2}-([a-z])+-[0-9]:\\d{12}:.+`);
};

// Derived from https://github.com/3nvi/panther/blob/master/deployments/bootstrap.yml#L557-L563
export const yupPasswordValidationSchema = Yup.string()
  .required()
  .min(12, 'Password must contain at least 12 characters')
  .matches(INCLUDE_UPPERCASE_REGEX, 'Password must contain at least 1 uppercase character')
  .matches(INCLUDE_LOWERCASE_REGEX, 'Password must contain at least 1 lowercase character')
  .matches(INCLUDE_SPECIAL_CHAR_REGEX, 'Password must contain at least 1 symbol')
  .matches(INCLUDE_DIGITS_REGEX, 'Password must contain  at least 1 number');

export const yupIntegrationLabelValidation = Yup.string()
  .required()
  .matches(SOURCE_LABEL_REGEX, 'Can only include alphanumeric characters, dashes and spaces')
  .max(32, 'Must be at most 32 characters');

export const yupWebhookValidation = Yup.string().url('Must be a valid webhook URL');
/**
 * checks whether the input is a valid UUID
 */
export const isGuid = (str: string) =>
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(str);

/**
 * caps the first letter of a string
 */
export const capitalize = (str: string) => str.charAt(0).toUpperCase() + str.slice(1);

/**
 * Given a server-received DateTime string, creates a proper display text for it. We manually
 * calculate the offset cause there is no available format-string that can display the UTC offset
 * as a single digit (all of them display it either as 03:00 or as 0300) and require string
 * manipulation which is harder
 * */
export const formatDatetime = (datetime: string, verbose = false, useUTC = false) => {
  // get the offset minutes and calculate the hours from them
  const utcOffset = dayjs(datetime).utcOffset() / 60;

  const suffix = useUTC
    ? 'UTC'
    : `G[M]T${utcOffset > 0 ? '+' : ''}${utcOffset !== 0 ? utcOffset : ''}`;
  const format = verbose ? `dddd, DD MMMM YYYY, HH:mm (${suffix})` : `YYYY-MM-DD HH:mm ${suffix}`;

  // properly format the date
  return (useUTC ? dayjs.utc(datetime) : dayjs(datetime)).format(format);
};

/** Slice text to 7 characters, mostly used for hashIds */
export const shortenId = (id: string) => id.slice(0, 7);

/** Checking if string is a proper hash */
export const isHash = (str: string) => CHECK_IF_HASH_REGEX.test(str);

/** Converts minutes integer to representative string i.e. 15 -> 15min,  120 -> 2h */
export const minutesToString = (minutes: number) =>
  minutes < 60 ? `${minutes}min` : `${minutes / 60}h`;

/** Converts seconds number to representative string i.e. 15 -> 15sec,  7200 -> 2 hours */
export const secondsToString = (seconds: number) => {
  if (seconds > 60 * 60 * 24 * 30 * 12) {
    return `${(seconds / (60 * 60 * 24 * 30 * 12)).toLocaleString()} years`;
  }
  if (seconds > 60 * 60 * 24 * 30) {
    return `${(seconds / (60 * 60 * 24 * 30)).toLocaleString()} months`;
  }
  if (seconds > 60 * 60 * 24) {
    return `${(seconds / (60 * 60 * 24)).toLocaleString()} days`;
  }
  if (seconds > 60 * 60) {
    return `${(seconds / (60 * 60)).toLocaleString()} hours`;
  }
  if (seconds > 60) {
    return `${(seconds / 60).toLocaleString()} min`;
  }
  return `${seconds.toLocaleString()} sec`;
};

/**
 * Given a server-received DateTime string, creates a proper time-ago display text for it.
 * */
export const getElapsedTime = (unixTimestamp: number) => {
  dayjs.extend(relativeTime);
  return dayjs.unix(unixTimestamp).fromNow();
};

/**
 * makes sure that it properly formats a JSON struct in order to be properly displayed within the
 * editor
 * @param code valid JSON
 * @returns String
 */
export const formatJSON = (code: { [key: string]: number | string }) =>
  JSON.stringify(code, null, '\t');

/**
 * Extends the resource by adding an `integrationLabel` field. We define two overloads for this
 * function
 * @param resource A resource that can be of type ResourceDetails, ResourceSummary or ComplianceItem
 * @param integrations A list of integrations with at least (integrationId & integrationType)
 */

export function extendResourceWithIntegrationLabel<T extends { integrationId?: string }>(
  resource: T,
  integrations: (Partial<ComplianceIntegration> &
    Pick<ComplianceIntegration, 'integrationId' | 'integrationLabel'>)[]
) {
  const matchingIntegration = integrations.find(i => i.integrationId === resource.integrationId);
  return {
    ...resource,
    integrationLabel: matchingIntegration?.integrationLabel || 'Cannot find account',
  };
}

/**
 * sums up the total number of items based on the active/suppresed count breakdown that the API
 * exposes
 */
export const getComplianceItemsTotalCount = (totals: ActiveSuppressCount) => {
  return (
    totals.active.pass +
    totals.active.fail +
    totals.active.error +
    totals.suppressed.pass +
    totals.suppressed.fail +
    totals.suppressed.error
  );
};

/**
 * sums up the total number of policies based on the severity and compliance status count breakdown
 * that the API exposes. With this function we can choose to aggregate only the failing policies
 * for a severity or even all of them, simply by passing the corresponding array of statuses to
 * aggregate.
 *
 * For example:
 * countPoliciesBySeverityAndStatus([], 'critical', ['fail', 'error']) would count the critical
 * policies that are either failing or erroring
 */
export const countPoliciesBySeverityAndStatus = (
  data: OrganizationReportBySeverity,
  severity: keyof OrganizationReportBySeverity,
  complianceStatuses: (keyof ComplianceStatusCounts)[]
) => {
  return sum(complianceStatuses.map(complianceStatus => data[severity][complianceStatus]));
};

/**
 * sums up the total number of resources based on the compliance status count breakdown
 * that the API exposes. With this function we can choose to aggregate only the failing resources
 * or even all of them, simply by passing the corresponding array of statuses to
 * aggregate.
 *
 * For example:
 * countResourcesByStatus([], ['fail', 'error']) would count the resources that are either failing
 * or erroring
 */
export const countResourcesByStatus = (
  data: ScannedResources,
  complianceStatuses: (keyof ComplianceStatusCounts)[]
) => {
  // aggregates the list of "totals" for each resourceType. The "total" for a resource type is the
  // aggregation of ['fail', 'error', ...] according to the parameter passed by the user
  return sum(
    data.byType.map(({ count }) =>
      sum(complianceStatuses.map(complianceStatus => count[complianceStatus]))
    )
  );
};

/**
 * A function that takes the whole GraphQL error as a payload and returns the message that should
 * be shown to the user
 */
export const extractErrorMessage = (error: ApolloError | ErrorResponse) => {
  // If there is a network error show something (we are already showing the network-error-modal though)
  if (error.networkError) {
    return "Can't perform any action because of a problem with your network";
  }

  // If there are no networkErrors or graphQL errors, then show the fallback
  if (!error.graphQLErrors || !error.graphQLErrors.length) {
    return 'A unpredicted server error has occurred';
  }

  // isolate the first GraphQL error. Currently all of our APIs return a single error. If we ever
  // return multiple, we should handle that for all items within the `graphQLErrors` key
  const { errorType, message } = error.graphQLErrors[0];
  switch (errorType) {
    case '401':
    case '403':
      return capitalize(message) || 'You are not authorized to perform this request';
    case '404':
      return capitalize(message) || "The resource you requested couldn't be found on our servers";
    default:
      return capitalize(message);
  }
};

// Copies a text to clipboard, with fallback for Safari and old-Edge
export const copyTextToClipboard = (text: string) => {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text);
  } else {
    const container = document.querySelector('[role="dialog"] [role="document"]') || document.body;
    const textArea = document.createElement('textarea');
    textArea.innerHTML = text;
    textArea.style.position = 'fixed'; // avoid scrolling to bottom
    container.appendChild(textArea);
    textArea.focus();
    textArea.select();
    document.execCommand('copy');
    container.removeChild(textArea);
  }
};

/**
 * A function that takes a text and returns a valid slug for it. Useful for filename and url
 * creation
 *
 * @param {String} text A string to slugify
 * @returns {String} A slugified string
 */
export function slugify(text: string) {
  return text
    .toString()
    .toLowerCase()
    .replace(/\s+/g, '-') // Replace spaces with -
    .replace(/[^\w-]+/g, '') // Remove all non-word chars
    .replace(/--+/g, '-') // Replace multiple - with single -
    .replace(/^-+/, '') // Trim - from start of text
    .replace(/-+$/, ''); // Trim - from end of text
}

export const isNumber = (value: string) => /^-{0,1}\d+$/.test(value);

/**
 * A function that returns true if the string consists of only non-whitespace characters
 * @param {string} value A string to test
 */
export const hasNoWhitespaces = (value: string) => /^\S+$/.test(value);

export const toStackNameFormat = (val: string) => val.replace(/ /g, '-').toLowerCase();

/*
Given a user, returns a human readable string to show for the user's name
*/
export const getUserDisplayName = (
  user: Pick<UserDetails, 'givenName' | 'familyName' | 'email'>
) => {
  if (!user) {
    return '';
  }

  if (user.givenName && user.familyName) {
    return `${user.givenName} ${user.familyName}`;
  }
  if (!user.givenName && user.familyName) {
    return user.familyName;
  }
  if (user.givenName && !user.familyName) {
    return user.givenName;
  }
  return user.email;
};

/**
 * Generates a random HEX color
 */
export const generateRandomColor = () => Math.floor(Math.random() * 16777215).toString(16);

/**
 * Converts a rem measurement (i.e. `0.29rem`) to pixels. Returns the number of pixels
 */
export const remToPx = (rem: string) => {
  return parseFloat(rem) * parseFloat(getComputedStyle(document.documentElement).fontSize);
};

/**
 * Appends a trailing slash if missing from a url.
 *
 * @param {String} url A URL to check
 * @returns {String} A URL with a trailing slash
 */
export const addTrailingSlash = (url: string) => {
  return url.endsWith('/') ? url : `${url}/`;
};

/**
 * Strips hashes and query params from a URI, returning the pathname
 *
 * @param {String} uri A relative URI
 * @returns {String} The same URI stripped of hashes and query params
 */
export const getPathnameFromURI = (uri: string) => uri.split(/[?#]/)[0];

export const getCurrentYear = () => {
  return dayjs().format('YYYY');
};

export const getGraphqlSafeDateRange = ({
  days = 0,
  hours = 0,
}: {
  days?: number;
  hours?: number;
}) => {
  const utcNow = dayjs.utc();
  const utcDaysAgo = utcNow.subtract(days, 'day').subtract(hours, 'hour');

  // the `startOf` and `endOf` help us have "constant" inputs for a few minutes, when we are using
  // those values as inputs to a GraphQL query. Of course there are edge cases.
  return [
    utcDaysAgo.startOf('hour').format('YYYY-MM-DDTHH:mm:ss[Z]'),
    utcNow.endOf('hour').format('YYYY-MM-DDTHH:mm:ss[Z]'),
  ];
};

export const formatNumber = (num: number): string => {
  return new Intl.NumberFormat().format(num);
};

/**
 *
 * Downloads the data  as a file
 *
 * @param data The data to save. Can be JSON, string, CSV, etc.
 * @param filename The name to save it under, along  with the extension. i.e. file.csv
 *
 */
export const downloadData = (data: string, filename: string) => {
  const extension = filename.split('.')[1];
  const blob = new Blob([data], {
    type: `text/${extension};charset=utf-8`,
  });
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.style.display = 'none';
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();

  window.URL.revokeObjectURL(url);
};

/**
 * Helper function that return key from Enumaration value
 * @param object
 * @param value
 */
export function getEnumKeyByValue(object: { [key: string]: string }, value: string) {
  return Object.keys(object).find(key => object[key] === value);
}

/**
 * Helper function that returns proper text for Alert Type
 * @param item AlertTypesEnum
 */
export const alertTypeToString = (item: AlertTypesEnum) => {
  switch (item) {
    case AlertTypesEnum.Rule:
      return 'Rule Matches';
    case AlertTypesEnum.RuleError:
      return 'Rule Errors';
    case AlertTypesEnum.Policy:
    default:
      return 'Policy Failures';
  }
};

/**
 * Converts a word to its plural form
 *
 * @returns {String} pluralized word
 *
 * @example
 * toPlural('example'); // => 'examples'
 * toPlural('example', 10); // => 'examples'
 * toPlural('example', 1); // => 'example'
 * toPlural('example', 'examplez', 10); // => 'examplez'
 * toPlural('example', 'examplez', 1); // => 'example'
 */
function toPlural(word: string): string;
function toPlural(word: string, count: number): string;
function toPlural(word: string, pluralForm: string, count: number): string;
function toPlural(word: string, pluralFormOrCount?: number | string, count?: number) {
  const plrl = typeof pluralFormOrCount === 'string' ? pluralFormOrCount : undefined;
  const cnt = typeof pluralFormOrCount === 'number' ? pluralFormOrCount : count;

  const pluralForm = plrl || `${word}s`;

  return cnt === 1 ? word : pluralForm;
}
export { toPlural };

/**
 * Compares two semver version
 * returns 1 if a version is bigger than b
 * returns -1 if a version is smaller than b
 * returns 0 if a version is equal to b
 * @returns Number [1,0,-1]
 */
export function compareSemanticVersion(a: string, b: string) {
  const av = a.match(/([0-9]+|[^0-9]+)/g);
  const bv = b.match(/([0-9]+|[^0-9]+)/g);
  for (;;) {
    let ia = av.shift();
    let ib = bv.shift();
    if (typeof ia === 'undefined' && typeof ib === 'undefined') {
      return 0;
    }
    if (typeof ia === 'undefined') {
      ia = '';
    }
    if (typeof ib === 'undefined') {
      ib = '';
    }

    const ian = parseInt(ia, 10);
    const ibn = parseInt(ib, 10);
    if (Number.isNaN(ian) || Number.isNaN(ibn)) {
      // non-numeric comparison
      if (ia < ib) {
        return -1;
      }
      if (ia > ib) {
        return 1;
      }
    } else {
      if (ian < ibn) {
        return -1;
      }
      if (ian > ibn) {
        return 1;
      }
    }
  }
}
