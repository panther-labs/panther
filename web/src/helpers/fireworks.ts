// @ts-ignore
const requestIdleCallback = window.requestIdleCallback || (cb => cb());

// Cause baby you're a firework, come on show em what you're worth
// https://www.youtube.com/watch?v=QGJuMBdaqIw
const shootFireworks = ({ duration = 3500 }: { duration?: number } = {}) => {
  // Lazy load it since we are only gonna need it once per installation
  import(/* webpackChunkName: "canvas-confetti" */ 'canvas-confetti').then(
    ({ default: confetti }) => {
      const shootRandomFirework = (side: 'left' | 'right') => {
        confetti({
          particleCount: 50,
          origin: {
            x: Math.random() * 0.2 + (side === 'left' ? 0.1 : 0.7),
            y: Math.random() - 0.2,
          },
          spread: 240,
        });
      };

      requestIdleCallback(() => {
        const interval = setInterval(() => {
          requestAnimationFrame(() => shootRandomFirework('left'));
          requestAnimationFrame(() => shootRandomFirework('right'));
        }, 250);

        setTimeout(() => clearInterval(interval), duration);
      });
    }
  );
};

export default shootFireworks;
