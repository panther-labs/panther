import { isMobile } from 'Helpers/utils';

export const isFastConnection = () => {
  if ('connection' in navigator) {
    return (navigator as any)?.connection?.effectiveType === '4g';
  }

  // optimistically assume a fast connection
  return true;
};

export const shouldSaveData = () => {
  if ('connection' in navigator) {
    return (navigator as any)?.connection?.saveData;
  }

  return isMobile;
};
