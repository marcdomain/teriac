// Seasonal touches: a Christmas hat on the logo from 1 December to 6 January (UTC),
// unless TERIAC_SEASONAL_LOGO=false.
export const christmas = (d = new Date()): boolean => d.getUTCMonth() === 11 || (d.getUTCMonth() === 0 && d.getUTCDate() <= 6);
