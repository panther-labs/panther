import React from 'react';
import { render } from 'test-utils';
import NavLink from './index';

describe('NavLink', () => {
  it('matches a URI regardless of hashes or query params', () => {
    const { getByText } = render(<NavLink to="/something/" label="alerts" icon="list" />, {
      initialRoute: '/something/#whatever?q=anything',
    });

    expect(getByText('alerts').closest('a')).toHaveAttribute('aria-current', 'page');
  });

  it('matches a URI regardless of trailing slashes', () => {
    const { getByText } = render(<NavLink to="/whatever" label="alerts" icon="list" />, {
      initialRoute: `/whatever/`,
    });

    expect(getByText('alerts').closest('a')).toHaveAttribute('aria-current', 'page');
  });

  it('matches children URIs', () => {
    const { getByText } = render(<NavLink to="/something/" label="alerts" icon="list" />, {
      initialRoute: '/something/particular/',
    });

    expect(getByText('alerts').closest('a')).toHaveAttribute('aria-current', 'page');
  });

  it('ignores unrelated URIs', () => {
    const { getByText } = render(<NavLink to="/something/" label="alerts" icon="list" />, {
      initialRoute: '/something-else/',
    });

    expect(getByText('alerts').closest('a')).not.toHaveAttribute('aria-current', 'page');
  });
});
