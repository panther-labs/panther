'use strict';
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
var __makeTemplateObject =
  (this && this.__makeTemplateObject) ||
  function (cooked, raw) {
    if (Object.defineProperty) {
      Object.defineProperty(cooked, 'raw', { value: raw });
    } else {
      cooked.raw = raw;
    }
    return cooked;
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.mockSendTestAlert = exports.useSendTestAlertLazyQuery = exports.useSendTestAlert = exports.SendTestAlertDocument = void 0;
var DeliveryResponseFull_generated_1 = require('../../../../../graphql/fragments/DeliveryResponseFull.generated');
var graphql_tag_1 = require('graphql-tag');
var ApolloReactHooks = require('@apollo/client');
exports.SendTestAlertDocument = graphql_tag_1.default(
  templateObject_1 ||
    (templateObject_1 = __makeTemplateObject(
      [
        '\n  query SendTestAlert($input: SendTestAlertInput!) {\n    sendTestAlert(input: $input) {\n      ...DeliveryResponseFull\n    }\n  }\n  ',
        '\n',
      ],
      [
        '\n  query SendTestAlert($input: SendTestAlertInput!) {\n    sendTestAlert(input: $input) {\n      ...DeliveryResponseFull\n    }\n  }\n  ',
        '\n',
      ]
    )),
  DeliveryResponseFull_generated_1.DeliveryResponseFull
);
/**
 * __useSendTestAlert__
 *
 * To run a query within a React component, call `useSendTestAlert` and pass it any options that fit your needs.
 * When your component renders, `useSendTestAlert` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useSendTestAlert({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
function useSendTestAlert(baseOptions) {
  return ApolloReactHooks.useQuery(exports.SendTestAlertDocument, baseOptions);
}
exports.useSendTestAlert = useSendTestAlert;
function useSendTestAlertLazyQuery(baseOptions) {
  return ApolloReactHooks.useLazyQuery(exports.SendTestAlertDocument, baseOptions);
}
exports.useSendTestAlertLazyQuery = useSendTestAlertLazyQuery;
function mockSendTestAlert(_a) {
  var data = _a.data,
    variables = _a.variables,
    errors = _a.errors;
  return {
    request: { query: exports.SendTestAlertDocument, variables: variables },
    result: { data: data, errors: errors },
  };
}
exports.mockSendTestAlert = mockSendTestAlert;
var templateObject_1;
