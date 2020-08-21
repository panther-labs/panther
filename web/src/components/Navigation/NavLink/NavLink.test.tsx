import React from 'react';
import { render } from 'test-utils';
import urls from 'Source/urls';
import NavLink from './index';

describe('NavLink', () => {
  it('matches a URI regardless of hashes or query params', () => {
    const url = urls.logAnalysis.alerts.list();
    const { getByText } = render(<NavLink to={url} label="alerts" icon="list" />, {
      initialRoute: `${url}#whatever?q=something`,
    });

    expect(getByText('alerts').closest('a')).toHaveAttribute('aria-current', 'page');
  });

  it('matches children URIs', () => {
    const { getByText } = render(
      <NavLink to={urls.logAnalysis.alerts.list()} label="alerts" icon="list" />,
      {
        initialRoute: urls.logAnalysis.alerts.details('id'),
      }
    );

    expect(getByText('alerts').closest('a')).toHaveAttribute('aria-current', 'page');
  });

  it('ignores unrelated URIs', () => {
    const { getByText } = render(
      <NavLink to={urls.logAnalysis.alerts.list()} label="alerts" icon="list" />,
      {
        initialRoute: urls.compliance.sources.list(),
      }
    );

    expect(getByText('alerts').closest('a')).not.toHaveAttribute('aria-current', 'page');
  });
});
