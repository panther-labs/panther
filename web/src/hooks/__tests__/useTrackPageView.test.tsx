import { renderHook } from 'test-utils';
import useTrackPageView from 'Hooks/useTrackPageView';
import { PageViewEnum, trackPageView } from 'Helpers/analytics';

jest.mock('Helpers/Analytics');

describe('useTrackPageView hook tests', () => {
  it('should call trackPageView only once', async () => {
    const { rerender } = renderHook(page => useTrackPageView(page), {
      initialProps: PageViewEnum.LogAnalysisOverview,
    });
    rerender(PageViewEnum.LogAnalysisOverview);
    expect(trackPageView).toHaveBeenCalledTimes(1);
    expect(trackPageView).toHaveBeenCalledWith({ page: PageViewEnum.LogAnalysisOverview });
  });

  it('should call trackPageView twice', async () => {
    const { rerender } = renderHook(page => useTrackPageView(page), {
      initialProps: PageViewEnum.LogAnalysisOverview,
    });
    expect(trackPageView).toHaveBeenCalledWith({ page: PageViewEnum.LogAnalysisOverview });
    rerender(PageViewEnum.ComplianceOverview);
    expect(trackPageView).toHaveBeenCalledWith({ page: PageViewEnum.ComplianceOverview });
    expect(trackPageView).toHaveBeenCalledTimes(2);
  });
});
