/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

import React from 'react';
import { PoliciesForResourceInput, ResourcesForPolicyInput } from 'Generated/schema';
import { Text, TextProps, defaultTheme } from 'pouncejs';

type Filters = PoliciesForResourceInput & ResourcesForPolicyInput;

interface TableComplianceFilterControlProps<FilterKey extends keyof Filters>
  extends Omit<TextProps, 'size'> {
  text: string;
  updateFilter: (filters: { [key: string]: Filters[FilterKey] }) => void;
  filterKey: FilterKey;
  filterValue: Filters[FilterKey];
  activeFilterValue?: Filters[FilterKey];
  count?: number;
  countColor?: keyof typeof defaultTheme.colors;
}

function TableComplianceFilterControl<FilterKey extends keyof Filters>({
  filterKey,
  filterValue,
  updateFilter,
  activeFilterValue,
  text,
  count,
  countColor,
  ...rest
}: TableComplianceFilterControlProps<FilterKey>): React.ReactElement {
  return (
    <Text
      {...rest}
      size="medium"
      p={2}
      color="grey300"
      is="button"
      borderRadius="medium"
      onClick={() => updateFilter({ [filterKey]: filterValue })}
      backgroundColor={filterValue === activeFilterValue ? 'grey50' : undefined}
    >
      {text}{' '}
      <Text size="medium" color={countColor} is="span">
        {count}
      </Text>
    </Text>
  );
}

export default TableComplianceFilterControl;
