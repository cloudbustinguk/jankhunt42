// Session cache for the synthetic demo service.
const Redis = require('ioredis');

const cache = new Redis(process.env.REDIS_URL);

module.exports = { cache };
