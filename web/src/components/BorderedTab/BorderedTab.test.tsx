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
import { render, fireEvent } from 'test-utils';
import { TabList, TabPanel, TabPanels, Tabs } from 'pouncejs';
import { BorderedTab } from './index';

describe('BorderedTab', () => {
  it('renders', () => {
    const { container } = render(
      <Tabs>
        <TabList>
          <BorderedTab>1</BorderedTab>
          <BorderedTab>2</BorderedTab>
        </TabList>
        <TabPanels>
          <TabPanel>One</TabPanel>
          <TabPanel>Two</TabPanel>
        </TabPanels>
      </Tabs>
    );
    expect(container).toMatchSnapshot();
  });

  it('works like a normal `Tab` element', () => {
    const { getByText } = render(
      <Tabs>
        <TabList>
          <BorderedTab>1</BorderedTab>
          <BorderedTab>2</BorderedTab>
        </TabList>
        <TabPanels>
          <TabPanel>One</TabPanel>
          <TabPanel>Two</TabPanel>
        </TabPanels>
      </Tabs>
    );

    expect(getByText('One')).toBeInTheDocument();
    expect(getByText('Two')).not.toBeVisible();

    fireEvent.click(getByText('2'));

    expect(getByText('One')).not.toBeVisible();
    expect(getByText('Two')).toBeInTheDocument();

    fireEvent.keyDown(getByText('2'), { key: 'ArrowLeft', code: 'ArrowLeft' });

    expect(getByText('One')).toBeInTheDocument();
    expect(getByText('Two')).not.toBeVisible();
  });
});
