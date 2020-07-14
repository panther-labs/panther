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

import type { UseTransitionProps, TransitionKeyProps, UseTransitionResult } from 'react-spring';

const realModule = jest.requireActual('react-spring');

module.exports = {
  ...realModule,
  useTransition: <TItem, DS extends Record<string, unknown>>(
    items: ReadonlyArray<TItem> | TItem | null | undefined,
    keys:
      | ((item: TItem) => TransitionKeyProps)
      | ReadonlyArray<TransitionKeyProps>
      | TransitionKeyProps
      | null,
    config: DS & UseTransitionProps<TItem, DS>
  ): UseTransitionResult<TItem, any>[] => {
    // Make sure to always render with the "final animation" styles (i.e. skip all the intermediate
    // transition styles)
    return realModule.useTransition(items, keys, config).map(transitionItem => ({
      ...transitionItem,
      props: !items || (Array.isArray(items) && !items.length) ? config.leave : config.enter,
    }));
  },
};
