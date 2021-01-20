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

import React from 'react';

const useHiddenOutline = () => {
  React.useEffect(() => {
    const handleTab = (e: KeyboardEvent) => {
      if (e.key === 'Tab' && !document.body.classList.contains('user-is-tabbing')) {
        // On tab, add a classname
        document.body.classList.add('user-is-tabbing');

        // and register a listener for 1 mouse click. When it happens, remove this classname
        const handleFirstClick = () => {
          document.body.classList.remove('user-is-tabbing');
          window.removeEventListener('mouseup', handleFirstClick, false);
        };
        window.addEventListener('mouseup', handleFirstClick, false);
      }
    };

    // Register a listener for tabs
    window.addEventListener('keyup', handleTab);
    return () => {
      window.removeEventListener('keyup', handleTab);
    };
  }, []);
};

export default useHiddenOutline;
