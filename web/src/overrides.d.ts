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

import 'yup';
import 'graphql';

/**
 * We declare a custom `unique` yup method and we want to expose it through the global package, so
 * that every module that imports yup can have access to it
 */
declare module 'yup' {
  export interface Schema<T> {
    unique<T>(message: string, key?: keyof T): this;
  }
}

/**
 * We are utilising AppSync, whose error doesn't conform to the standardized error set by GraphQL
 * itself (what a surprise). Thus, we need to add the Fields that AppSync returns to the schema of
 * the GraphQL error
 */
declare module 'graphql' {
  export interface GraphQLError {
    errorType: string;
    errorInfo?: any;
  }
}

/**
 * We want to override window.requestIdleCallback because Safari doesn't support it.
 * We declare the new function in config.ts
 */
declare global {
  interface Window {
    requestIdleCallback: (Function) => void;
  }
}
