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
import { render, buildAnalysisPack } from 'test-utils';
import PackDetailsBanner from './index';

describe('PackDetailsBanner', () => {
  it('renders the correct data', async () => {
    const pack = buildAnalysisPack({ updateAvailable: true });
    const { getByText } = render(<PackDetailsBanner pack={pack} />);

    expect(getByText(pack.displayName)).toBeInTheDocument();
    expect(getByText(pack.description)).toBeInTheDocument();
    expect(getByText('UPDATE AVAILABLE')).toBeInTheDocument();
    expect(getByText('Update Pack')).toBeInTheDocument();
    expect(getByText('Enabled')).toBeInTheDocument();
  });

  it("doesn't render 'Update Available' indication", async () => {
    const pack = buildAnalysisPack({ updateAvailable: false });
    const { getByText, queryByText } = render(<PackDetailsBanner pack={pack} />);

    expect(getByText(pack.displayName)).toBeInTheDocument();
    expect(getByText(pack.description)).toBeInTheDocument();
    expect(queryByText('UPDATE AVAILABLE')).not.toBeInTheDocument();
    expect(getByText('Update Pack')).toBeInTheDocument();
    expect(getByText('Enabled')).toBeInTheDocument();
  });
});
