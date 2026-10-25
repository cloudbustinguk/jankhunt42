// Working days between two dates, inclusive, skipping weekends.
function workingDays(start, end) {
  let days = 0;
  for (let d = new Date(start); d <= end; d.setDate(d.getDate() + 1)) {
    const wd = d.getDay();
    if (wd !== 0 && wd !== 6) days += 1;
  }
  return days;
}

module.exports = { workingDays };
