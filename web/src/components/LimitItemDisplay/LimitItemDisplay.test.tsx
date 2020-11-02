import React from 'react';
import { render, fireEvent } from 'test-utils';
import LimitItemDisplay from './LimitItemDisplay';

describe('LimitItemDisplay', () => {
  it('shows all the items if they are equal to or less than the limit', () => {
    const { getByText } = render(
      <LimitItemDisplay limit={2}>
        <div>One</div>
        <div>Two</div>
      </LimitItemDisplay>
    );

    expect(getByText('One')).toBeInTheDocument();
    expect(getByText('Two')).toBeInTheDocument();
  });

  it('shows less items if they are more than the limit and displays the rest in a tooltip', async () => {
    const { queryByText, findByText } = render(
      <LimitItemDisplay limit={2}>
        <div>One</div>
        <div>Two</div>
        <div>Three</div>
        <div>Four</div>
      </LimitItemDisplay>
    );

    expect(queryByText('Three')).not.toBeInTheDocument();
    expect(queryByText('Four')).not.toBeInTheDocument();

    fireEvent.mouseEnter(queryByText('+2'));

    expect(await findByText('Three')).toBeInTheDocument();
    expect(queryByText('Four')).toBeInTheDocument();
  });

  it('matches snapshot', async () => {
    const { container, getByText, findByText } = render(
      <LimitItemDisplay limit={2}>
        <div>One</div>
        <div>Two</div>
        <div>Three</div>
        <div>Four</div>
      </LimitItemDisplay>
    );
    expect(container).toMatchSnapshot();

    fireEvent.mouseEnter(getByText('+2'));
    expect(await findByText('Three')).toBeInTheDocument();

    expect(container).toMatchSnapshot();
  });
});
