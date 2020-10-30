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
exports.DeliveryResponseFull = void 0;
var graphql_tag_1 = require('graphql-tag');
exports.DeliveryResponseFull = graphql_tag_1.default(
  templateObject_1 ||
    (templateObject_1 = __makeTemplateObject(
      [
        '\n  fragment DeliveryResponseFull on DeliveryResponse {\n    outputId\n    statusCode\n    message\n    success\n    dispatchedAt\n  }\n',
      ],
      [
        '\n  fragment DeliveryResponseFull on DeliveryResponse {\n    outputId\n    statusCode\n    message\n    success\n    dispatchedAt\n  }\n',
      ]
    ))
);
var templateObject_1;
