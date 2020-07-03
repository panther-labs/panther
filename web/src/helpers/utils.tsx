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
import mapValues from 'lodash-es/mapValues';
import sum from 'lodash-es/sum';
import { ErrorResponse } from 'apollo-link-error';
import { ApolloError } from '@apollo/client';

export const isMobile = /Mobi|Android/i.test(navigator.userAgent);

// Generate a new secret code that contains metadata of issuer and user email
export const formatSecretCode = (code: string, email: string): string => {
  const issuer = 'Panther';
  return `otpauth://totp/${email}?secret=${code}&issuer=${issuer}`;
};

export const getArnRegexForService = (awsService: string) => {
  return new RegExp(`arn:aws:${awsService.toLowerCase()}:([a-z]){2}-([a-z])+-[0-9]:\\d{12}:.+`);
};

export const createYupPasswordValidationSchema = () =>
  Yup.string()
    .required()
    .min(14, 'Must be at least 14 characters')
    .matches(INCLUDE_DIGITS_REGEX, 'Include at least 1 digit')
    .matches(INCLUDE_LOWERCASE_REGEX, 'Include at least 1 lowercase character')
    .matches(INCLUDE_UPPERCASE_REGEX, 'Include at least 1 uppercase character')
    .matches(INCLUDE_SPECIAL_CHAR_REGEX, 'Include at least 1 special character');

export const integrationLabelValidation = () =>
  Yup.string()
    .required()
    .matches(SOURCE_LABEL_REGEX, 'Can only include alphanumeric characters, dashes and spaces')
    .max(32, 'Must be at most 32 characters');

export const webhookValidation = () => Yup.string().url('Must be a valid webhook URL');
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
export const formatDatetime = (datetime: string) => {
  // get the offset minutes and calculate the hours from them
  const utcOffset = dayjs(datetime).utcOffset() / 60;

  // properly format the date
  return dayjs(datetime).format(
    `YYYY-MM-DD HH:mm G[M]T${utcOffset > 0 ? '+' : ''}${utcOffset !== 0 ? utcOffset : ''}`
  );
};

/**
 * Given a dayjs format string, create a partial that accepts a datestring that can convert
 * UTC -> Local time and from Local time -> UTC.
 *
 * This is primarily used when converting local time in a frontend form with URL parameters in UTC.
 */
export const formatTime = (format?: string) => (
  datetime: string,
  utcIn?: boolean,
  utcOut?: boolean
) => {
  // Set the initial date context as utc or local
  let date = utcIn ? dayjs.utc(datetime) : dayjs(datetime);

  // Calculate offset in hours for the default format string
  const utcOffsetHours = dayjs(datetime).utcOffset() / 60;

  // Perform the proper conversion of time units
  if (!utcIn && utcOut) {
    date = date.subtract(date.utcOffset(), 'minute');
  }

  // Use the provided partial or our default
  const fmt =
    format ||
    `YYYY-MM-DD HH:mm G[M]T${utcOffsetHours > 0 ? '+' : ''}${
      utcOffsetHours !== 0 ? utcOffsetHours : ''
    }`;

  // Finally, return the time in UTC or Local time
  return utcOut ? date.format(fmt) : date.local().format(fmt);
};

/** Slice text to 7 characters, mostly used for hashIds */
export const shortenId = (id: string) => id.slice(0, 7);

/** Checking if string is a proper hash */
export const isHash = (str: string) => CHECK_IF_HASH_REGEX.test(str);

/** Converts minutes integer to representative string i.e. 15 -> 15min,  120 -> 2h */
export const minutesToString = (minutes: number) =>
  minutes < 60 ? `${minutes}min` : `${minutes / 60}h`;

/**
 * Given a server-received DateTime string, creates a proper time-ago display text for it.
 * */
export const getElapsedTime = (unixTimestamp: number) => {
  dayjs.extend(relativeTime);
  return dayjs.unix(unixTimestamp).fromNow();
};

/** Converts any value of the object that is an array to a comma-separated string */
export const convertObjArrayValuesToCsv = (obj: { [key: string]: any }) =>
  mapValues(obj, v => (Array.isArray(v) ? v.join(',') : v));

/** URI encoding for specified fields in object */
export const encodeParams = (obj: { [key: string]: any }, fields: [string]) =>
  mapValues(obj, (v, key) => (fields.includes(key) ? encodeURIComponent(v) : v));
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
      return message || 'You are not authorized to perform this request';
    case '404':
      return message || "The resource you requested couldn't be found on our servers";
    default:
      return message;
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

export const toStackNameFormat = (val: string) => val.replace(/ /g, '-').toLowerCase();

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
