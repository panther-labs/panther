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

export enum ChartsThemeEnum {
  light = 'light',
  dark = 'dark',
}

export const LineColors = {
  'AWS.Cloudtrail': '#FDCA00',
};

export const ThemeOptions: { [key in ChartsThemeEnum]: any } = {
  [ChartsThemeEnum.light]: {
    backgroundColor: '#FFFFFF',
  },
  [ChartsThemeEnum.dark]: {
    backgroundColor: '#4c4c4c',
  },
};

export enum ChartTypesEnum {
  Lines,
  ZoomableLines,
}

export type ChartType = keyof typeof ChartTypesEnum;

export type ChartThemeType = keyof typeof ChartsThemeEnum;
