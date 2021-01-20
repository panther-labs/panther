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

import { renderHook, fireEvent } from 'test-utils';
import useHiddenOutline from './useHiddenOutline';

test('it adds a tab-related class when <Tab> is pressed and removes it on mouse click', () => {
  renderHook(() => useHiddenOutline());

  fireEvent.keyUp(document.body, { key: 'Tab' });
  expect(document.body).toHaveClass('user-is-tabbing');

  fireEvent.keyPress(document.body, { key: 'Enter' });
  expect(document.body).toHaveClass('user-is-tabbing');

  fireEvent.mouseUp(document.body);
  expect(document.body).not.toHaveClass('user-is-tabbing');
});
