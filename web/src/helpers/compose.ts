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

type Func<T extends any[], R> = (...a: T) => R;

// TODO: fix Function types
// Don't use `Function` as a type. The `Function` type accepts any function-like value.
// It provides no type safety when calling the function, which can be a common source of bugs.
// It also accepts things like class declarations, which will throw at runtime as they will not be called with `new`.
// If you are expecting the function to accept certain arguments, you should explicitly define the function shape
//
/* eslint-disable @typescript-eslint/ban-types */

export function compose<A, B, C, T extends any[], R>(
  f1: (c: C) => R,
  f2: (b: B) => C,
  f3: (a: A) => B,
  f4: Func<T, A>
): Func<T, R>;

export function compose<R>(f1: (a: any) => R, ...funcs: Function[]): (...args: any[]) => R;
export function compose<R>(...funcs: Function[]): (...args: any[]) => R;

export function compose(...funcs: Function[]) {
  if (funcs.length === 0) {
    // infer the argument type so it is usable in inference down the line
    return <T>(arg: T) => arg;
  }

  if (funcs.length === 1) {
    return funcs[0];
  }

  return funcs.reduce((a, b) => (...args: any) => a(b(...args)));
}
