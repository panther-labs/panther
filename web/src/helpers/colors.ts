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

interface StringToHSL {
  str: string;
  hue?: [number, number];
  saturation?: [number, number];
  lightness?: [number, number];
}

/**
 * Restricts a given number in the range specified
 */
const restrictToRange = (number, min, max) => {
  const diff = max - min;
  const x = ((number % diff) + diff) % diff;
  return x + min;
};

/**
 * Given a string, it creates a hash which will map to an HSL color which can be "restricted" in
 * order to produce specific types of colors
 */
const stringToHSL = ({
  str,
  hue = [0, 360],
  saturation = [0, 100],
  lightness = [0, 100],
}: StringToHSL) => {
  if (!str.length) {
    return `hsl(0,0,0)`;
  }

  /* eslint-disable no-bitwise */
  let hash = 0;
  str.split('').forEach((letter, index) => {
    hash = str.charCodeAt(index) + ((hash << 5) - hash);
    hash &= hash;
  });
  /* eslint-enable no-bitwise */

  const h = restrictToRange(hash, hue[0], hue[1]);
  const s = restrictToRange(hash, saturation[0], saturation[1]);
  const l = restrictToRange(hash, lightness[0], lightness[1]);

  return `hsl(${h}, ${s}%, ${l}%)`;
};

export const stringToPaleColor = (str: string) =>
  stringToHSL({ str, saturation: [20, 50], lightness: [30, 80] });
