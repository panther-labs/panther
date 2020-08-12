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

import faker from 'faker';
import { fireEvent } from '@testing-library/react';

/**
 * Selects a random element from an array
 * @param array An array of items
 */
export function randomFromArray<T>(array: T[] | ReadonlyArray<T>) {
  return faker.random.arrayElement(array);
}

/**
 * Generates a random array of elements through a single item-generating function
 * @param func A function that generates an item
 * @param min The min length of the random array
 * @param max The max length of the random array
 */
export function generateRandomArray<T>(func: (index: number) => T, min = 0, max = 10) {
  const randomArrayLength = faker.random.number({ min, max, precision: 1 });
  return [...Array(randomArrayLength)].map((_, index) => func(index));
}

/**
 *
 * @param ms milliseconds to wait
 * Waits for a specific number of time
 */
export function waitMs(ms = 0) {
  return new Promise(r => setTimeout(r, ms));
}

/**
 * Fires all related events that would simulate a typical click. A lot of Reach-UI components expect
 * mouseevents instead of click ones. This helper allows us to use all of them at once
 * @param element HTML element
 */
export function fireClickAndMouseEvents(element: HTMLElement) {
  fireEvent.mouseMove(element);
  fireEvent.mouseDown(element);
  fireEvent.mouseUp(element);
  fireEvent.click(element);
}
