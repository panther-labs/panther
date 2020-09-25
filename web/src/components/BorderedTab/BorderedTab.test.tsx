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
