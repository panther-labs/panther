export const eventData = {
  metricNames: [
    {
      metricName: 'EventsProcessed',
      seriesData: [
        {
          label: 'AWS.ALB',
          timestamps: ['2020-07-09T22:00:00Z', '2020-07-09T21:00:00Z', '2020-07-09T20:00:00Z'],
          values: [6, 2, 2],
        },
        {
          label: 'AWS.VPCFlow',
          timestamps: ['2020-07-09T22:00:00Z', '2020-07-09T21:00:00Z', '2020-07-09T20:00:00Z'],
          values: [885, 1654, 350],
        },
        {
          label: 'AWS.S3',
          timestamps: ['2020-07-09T22:00:00Z', '2020-07-09T21:00:00Z', '2020-07-09T20:00:00Z'],
          values: [1350, 547, 621],
        },
      ],
    },
  ],
  fromDate: '2020-07-09T12:00:00Z',
  toDate: '2020-07-09T23:00:00Z',
  intervalHours: 1,
};
