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
